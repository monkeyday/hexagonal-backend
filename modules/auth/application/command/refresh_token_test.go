package command

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"

	coreerror "sc/core/error"
	"sc/core/usecase"
	"sc/modules/auth/application/define"
	"sc/modules/auth/domain/entity"
	autherrors "sc/modules/auth/errors"
	"testing"
	"time"
)

func TestRefreshTokenUseCase_Atomicity(t *testing.T) {
	ctx := context.Background()
	user := newTestUser()

	newValidRT := func() *entity.RefreshToken {
		return entity.NewRefreshToken("user-1", "", &entity.IssuedTokens{RefreshToken: "valid-refresh-token", Scope: entity.MustParseScope("openid")})
	}

	t.Run("concurrent same-token refresh — exactly one succeeds", func(t *testing.T) {
		rtRepo := newMockRefreshTokenRepo(newValidRT())
		mod := usecase.NewRegistry()
		mod.Register(RefreshTokenCommand{}, NewRefreshTokenUseCase(define.Dependencies{
			UoW:              &transactionalMockUoW{rtRepo: rtRepo},
			JWTSvc:           &mockJwtService{accessToken: "new-access", refreshToken: "new-refresh"},
			UserRepo:         newMockRepo(user),
			RefreshTokenRepo: rtRepo,
			GrantRepo:        newMockGrantRepo(),
			ClientRegistry:   newMockClientRegistry(newTestClient(t, "APP_ID", entity.ClientAuthNone)),
		}))

		type result struct {
			resp any
			err  error
		}
		results := make([]result, 2)
		var wg sync.WaitGroup
		wg.Add(2)
		for i := range results {
			i := i
			go func() {
				defer wg.Done()
				resp, err := mod.Dispatch(ctx, &RefreshTokenCommand{
					GrantType:    "refresh_token",
					ClientID:     "APP_ID",
					RefreshToken: "valid-refresh-token",
				})
				results[i] = result{resp, err}
			}()
		}
		wg.Wait()

		var successes, invalidToken int
		for _, r := range results {
			if r.err == nil {
				successes++
			} else if e, ok := r.err.(interface{ Code() coreerror.ErrCode }); ok && e.Code() == autherrors.InvalidRefreshToken {
				invalidToken++
			} else {
				t.Errorf("unexpected error: %v", r.err)
			}
		}
		if successes != 1 {
			t.Errorf("successes = %d, want 1", successes)
		}
		if invalidToken != 1 {
			t.Errorf("InvalidRefreshToken errors = %d, want 1", invalidToken)
		}
	})

	t.Run("rotation preserves AuthenticatedAt and GrantID", func(t *testing.T) {
		rt := newValidRT()
		originalAuthAt := rt.AuthenticatedAt
		originalGrantID := rt.GrantID
		jwtSvc := &mockJwtService{accessToken: "new-access", refreshToken: "new-refresh"}
		rtRepo := newMockRefreshTokenRepo(rt)
		mod := usecase.NewRegistry()
		mod.Register(RefreshTokenCommand{}, NewRefreshTokenUseCase(define.Dependencies{
			UoW:              &mockUoW{},
			JWTSvc:           jwtSvc,
			UserRepo:         newMockRepo(user),
			RefreshTokenRepo: rtRepo,
			GrantRepo:        newMockGrantRepo(),
			ClientRegistry:   newMockClientRegistry(newTestClient(t, "APP_ID", entity.ClientAuthNone)),
		}))

		resp, err := mod.Dispatch(ctx, &RefreshTokenCommand{
			GrantType:    "refresh_token",
			ClientID:     "APP_ID",
			RefreshToken: "valid-refresh-token",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		newHash := entity.Hash(resp.(*define.TokenResponse).RefreshToken)
		newRT := rtRepo.tokens[newHash]
		if newRT == nil {
			t.Fatal("new refresh token not found in repo")
		}
		if !newRT.AuthenticatedAt.Equal(originalAuthAt) {
			t.Errorf("AuthenticatedAt not preserved across rotation: got %v, want %v", newRT.AuthenticatedAt, originalAuthAt)
		}
		if newRT.GrantID != originalGrantID {
			t.Errorf("GrantID not preserved across rotation: got %q, want %q", newRT.GrantID, originalGrantID)
		}
		// sid/grant handed to issuance equals the original refresh token's GrantID
		if jwtSvc.capturedAccessGrantID != string(originalGrantID) {
			t.Errorf("sid passed to GenAccessToken = %q, want %q", jwtSvc.capturedAccessGrantID, originalGrantID)
		}
		if newRT.Scope.String() != rt.Scope.String() {
			t.Errorf("Scope not preserved across rotation: got %q, want %q", newRT.Scope.String(), rt.Scope.String())
		}
	})

	t.Run("legacy token with empty GrantID — rotated token gets a fresh non-empty grant matching issuance", func(t *testing.T) {
		// Simulate a refresh token stored before grant linkage landed (GrantID == "").
		rt := newValidRT()
		rt.GrantID = "" // legacy token
		jwtSvc := &mockJwtService{accessToken: "new-access", refreshToken: "new-refresh"}
		rtRepo := newMockRefreshTokenRepo(rt)
		mod := usecase.NewRegistry()
		mod.Register(RefreshTokenCommand{}, NewRefreshTokenUseCase(define.Dependencies{
			UoW:              &mockUoW{},
			JWTSvc:           jwtSvc,
			UserRepo:         newMockRepo(user),
			RefreshTokenRepo: rtRepo,
			GrantRepo:        newMockGrantRepo(),
			ClientRegistry:   newMockClientRegistry(newTestClient(t, "APP_ID", entity.ClientAuthNone)),
		}))

		resp, err := mod.Dispatch(ctx, &RefreshTokenCommand{
			GrantType:    "refresh_token",
			ClientID:     "APP_ID",
			RefreshToken: "valid-refresh-token",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		newHash := entity.Hash(resp.(*define.TokenResponse).RefreshToken)
		newRT := rtRepo.tokens[newHash]
		if newRT == nil {
			t.Fatal("new refresh token not found in repo")
		}
		if newRT.GrantID == "" {
			t.Error("rotated token from a legacy (empty GrantID) original must have a non-empty GrantID")
		}
		// The grant used for issuance (captured by the mock) must equal the rotated token's GrantID
		if string(newRT.GrantID) != jwtSvc.capturedAccessGrantID {
			t.Errorf("rotated GrantID = %q, want same as issuance grantID = %q",
				newRT.GrantID, jwtSvc.capturedAccessGrantID)
		}
	})

	t.Run("Save fails — old token not revoked (transactional rollback)", func(t *testing.T) {
		rtRepo := &mockRefreshTokenRepo{
			tokens:  map[string]*entity.RefreshToken{entity.Hash("valid-refresh-token"): newValidRT()},
			saveErr: errors.New("db error"),
		}
		mod := usecase.NewRegistry()
		mod.Register(RefreshTokenCommand{}, NewRefreshTokenUseCase(define.Dependencies{
			UoW:              &transactionalMockUoW{rtRepo: rtRepo},
			JWTSvc:           &mockJwtService{accessToken: "new-access", refreshToken: "new-refresh"},
			UserRepo:         newMockRepo(user),
			RefreshTokenRepo: rtRepo,
			GrantRepo:        newMockGrantRepo(),
			ClientRegistry:   newMockClientRegistry(newTestClient(t, "APP_ID", entity.ClientAuthNone)),
		}))

		_, err := mod.Dispatch(ctx, &RefreshTokenCommand{
			GrantType:    "refresh_token",
			ClientID:     "APP_ID",
			RefreshToken: "valid-refresh-token",
		})
		if err == nil {
			t.Fatal("expected error, got nil")
		}

		// After rollback, old token must still be valid
		oldHash := entity.Hash("valid-refresh-token")
		if rt := rtRepo.tokens[oldHash]; rt == nil || rt.RevokedAt != nil {
			t.Error("old refresh token must remain unrevoked after failed rotation (rollback)")
		}
		// New token must not have been persisted
		if len(rtRepo.tokens) != 1 {
			t.Errorf("expected exactly 1 token in repo after rollback, got %d", len(rtRepo.tokens))
		}
	})
}

// TestRefreshTokenUseCase_GrantCheck covers the grant check inside the rotation
// transaction (grant-linkage.md §10, PR8): a dead grant stops the chain, and a
// live one has its expiry pushed out so it outlives the token just issued.
func TestRefreshTokenUseCase_GrantCheck(t *testing.T) {
	ctx := context.Background()
	user := newTestUser()

	// setup returns a use case whose refresh token belongs to grant, plus the
	// repos so the test can inspect what the rotation did. A nil grant leaves
	// the grant repo empty, which is the legacy (pre-linkage) chain.
	setup := func(t *testing.T, grant *entity.Grant) (*usecase.Registry, *mockRefreshTokenRepo, *mockGrantRepo, *entity.RefreshToken) {
		t.Helper()
		rt := entity.NewRefreshToken("user-1", "", &entity.IssuedTokens{RefreshToken: "valid-refresh-token", Scope: entity.MustParseScope("openid")})
		grantRepo := newMockGrantRepo()
		if grant != nil {
			grant.ID = rt.GrantID
			if err := grantRepo.Save(ctx, grant); err != nil {
				t.Fatalf("seeding grant: %v", err)
			}
		}
		rtRepo := newMockRefreshTokenRepo(rt)
		mod := usecase.NewRegistry()
		mod.Register(RefreshTokenCommand{}, NewRefreshTokenUseCase(define.Dependencies{
			UoW:              &transactionalMockUoW{rtRepo: rtRepo},
			JWTSvc:           &mockJwtService{accessToken: "new-access", refreshToken: "new-refresh"},
			UserRepo:         newMockRepo(user),
			RefreshTokenRepo: rtRepo,
			GrantRepo:        grantRepo,
			ClientRegistry:   newMockClientRegistry(newTestClient(t, "APP_ID", entity.ClientAuthNone)),
		}))
		return mod, rtRepo, grantRepo, rt
	}

	dispatch := func(mod *usecase.Registry) (any, error) {
		return mod.Dispatch(ctx, &RefreshTokenCommand{
			GrantType:    "refresh_token",
			ClientID:     "APP_ID",
			RefreshToken: "valid-refresh-token",
		})
	}

	t.Run("revoked grant — rotation rejected, old token left unrevoked", func(t *testing.T) {
		grant := entity.NewGrant("user-1", "")
		grant.RevokedAt = new(time.Now())
		mod, rtRepo, _, rt := setup(t, grant)

		_, err := dispatch(mod)
		if err == nil {
			t.Fatal("expected rotation to be rejected on a revoked grant, got nil error")
		}
		e, ok := err.(interface{ Code() coreerror.ErrCode })
		if !ok || e.Code() != autherrors.InvalidRefreshToken {
			t.Fatalf("error = %v, want InvalidRefreshToken", err)
		}
		if stored := rtRepo.tokens[rt.TokenHash]; stored == nil || stored.RevokedAt != nil {
			t.Error("old refresh token must be left unrevoked when the grant check rejects the rotation")
		}
		if len(rtRepo.tokens) != 1 {
			t.Errorf("expected no new token persisted, got %d tokens", len(rtRepo.tokens))
		}
	})

	t.Run("expired grant — rotation rejected", func(t *testing.T) {
		grant := entity.NewGrant("user-1", "")
		grant.ExpiresAt = time.Now().Add(-time.Minute)
		mod, _, _, _ := setup(t, grant)

		_, err := dispatch(mod)
		if err == nil {
			t.Fatal("expected rotation to be rejected on an expired grant, got nil error")
		}
		e, ok := err.(interface{ Code() coreerror.ErrCode })
		if !ok || e.Code() != autherrors.InvalidRefreshToken {
			t.Fatalf("error = %v, want InvalidRefreshToken", err)
		}
	})

	t.Run("missing grant (pre-linkage chain) — rotation succeeds, fails open", func(t *testing.T) {
		mod, _, grantRepo, _ := setup(t, nil)

		if _, err := dispatch(mod); err != nil {
			t.Fatalf("rotation must fail open when the grant is absent: %v", err)
		}
		if len(grantRepo.grants) != 0 {
			t.Errorf("expected no grant to be created by the check, got %d", len(grantRepo.grants))
		}
	})

	// assertGrantOutlives is the assertion the whole extension mechanism exists
	// for. Checking the grant against now+TTL instead would pass even when the
	// grant expires first, which is precisely the failure it must catch.
	assertGrantOutlives := func(t *testing.T, grant *entity.Grant, newRT *entity.RefreshToken) {
		t.Helper()
		if !grant.ExpiresAt.After(newRT.ExpiresAt) {
			t.Errorf("grant ExpiresAt = %v, want strictly after the rotated token's %v",
				grant.ExpiresAt, newRT.ExpiresAt)
		}
	}

	rotatedToken := func(t *testing.T, rtRepo *mockRefreshTokenRepo) *entity.RefreshToken {
		t.Helper()
		newRT := rtRepo.tokens[entity.Hash("new-refresh")]
		if newRT == nil {
			t.Fatal("rotated refresh token not persisted")
		}
		return newRT
	}

	t.Run("active grant — ExpiresAt extended past the token just issued", func(t *testing.T) {
		grant := entity.NewGrant("user-1", "")
		grant.ExpiresAt = time.Now().Add(time.Hour) // close to collection
		mod, rtRepo, grantRepo, rt := setup(t, grant)

		if _, err := dispatch(mod); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		stored := grantRepo.grants[rt.GrantID]
		if stored == nil {
			t.Fatal("grant not found after rotation")
		}
		assertGrantOutlives(t, stored, rotatedToken(t, rtRepo))
	})

	// A grant that cannot be stored must fail issuance rather than be swallowed,
	// so later code may assume grant rows are complete.
	t.Run("grant store fails — rotation fails, nothing persisted", func(t *testing.T) {
		mod, rtRepo, grantRepo, rt := setup(t, nil)
		rt.GrantID = "" // legacy row: this rotation mints and saves a grant
		grantRepo.saveErr = errors.New("db down")

		if _, err := dispatch(mod); err == nil {
			t.Fatal("a grant-store failure must fail the rotation, not be swallowed")
		}
		if rtRepo.tokens[entity.Hash("new-refresh")] != nil {
			t.Error("no refresh token may be persisted when its grant could not be saved")
		}
		if stored := rtRepo.tokens[rt.TokenHash]; stored == nil || stored.RevokedAt != nil {
			t.Error("the presented token must be left unrevoked when the rotation fails")
		}
	})

	// The legacy first rotation mints its grant outside the transaction, so it
	// is the one issuing path where the grant is written before the transaction
	// that saves the token it covers.
	t.Run("legacy chain joining a fresh grant — the new grant covers the new token", func(t *testing.T) {
		mod, rtRepo, grantRepo, rt := setup(t, nil)
		rt.GrantID = "" // pre-linkage row: carries no grant of its own
		ops := &opsLog{}
		rtRepo.ops = ops
		grantRepo.ops = ops

		if _, err := dispatch(mod); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Grant first here too, even though this grant is written outside the
		// rotation transaction: a partial write must not leave a token whose
		// grant is missing.
		if got := ops.all(); !slices.Equal(got, []string{"save_grant", "save_token"}) {
			t.Errorf("save order = %v, want [save_grant save_token]", got)
		}
		newRT := rotatedToken(t, rtRepo)
		if len(grantRepo.grants) != 1 {
			t.Fatalf("expected exactly one freshly minted grant, got %d", len(grantRepo.grants))
		}
		stored := grantRepo.grants[newRT.GrantID]
		if stored == nil {
			t.Fatalf("the rotated token's grant %q was not persisted", newRT.GrantID)
		}
		assertGrantOutlives(t, stored, newRT)
	})
}

func TestRefreshTokenUseCase_ReuseDetection(t *testing.T) {
	ctx := context.Background()

	newUseCase := func(rtRepo *mockRefreshTokenRepo) *usecase.Registry {
		mod := usecase.NewRegistry()
		mod.Register(RefreshTokenCommand{}, NewRefreshTokenUseCase(define.Dependencies{
			UoW:              &mockUoW{},
			JWTSvc:           &mockJwtService{accessToken: "new-access", refreshToken: "new-refresh"},
			UserRepo:         newMockRepo(newTestUser()),
			RefreshTokenRepo: rtRepo,
			GrantRepo:        newMockGrantRepo(),
			ClientRegistry:   newMockClientRegistry(newTestClient(t, "APP_ID", entity.ClientAuthNone)),
		}))
		return mod
	}

	cmdFor := func(token string) *RefreshTokenCommand {
		return &RefreshTokenCommand{GrantType: "refresh_token", ClientID: "APP_ID", RefreshToken: token}
	}

	assertErrCode := func(t *testing.T, err error, want coreerror.ErrCode) {
		t.Helper()
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		if e, ok := err.(interface{ Code() coreerror.ErrCode }); !ok || e.Code() != want {
			t.Fatalf("got err %v, want err_code %d", err, want)
		}
	}

	t.Run("replayed revoked token — only that grant's tokens revoked, other grant untouched", func(t *testing.T) {
		stolenGrant := entity.NewGrantID()
		otherGrant := entity.NewGrantID()

		stolen := entity.NewRefreshToken("user-1", "", &entity.IssuedTokens{RefreshToken: "stolen-token", Scope: entity.MustParseScope("openid")})
		stolen.GrantID = stolenGrant
		stolen.RevokedAt = new(time.Now().Add(-time.Minute))
		sameGrantSibling := entity.NewRefreshToken("user-1", "", &entity.IssuedTokens{RefreshToken: "same-grant-sibling", Scope: entity.MustParseScope("openid")})
		sameGrantSibling.GrantID = stolenGrant
		otherGrantToken := entity.NewRefreshToken("user-1", "", &entity.IssuedTokens{RefreshToken: "other-grant-token", Scope: entity.MustParseScope("openid")})
		otherGrantToken.GrantID = otherGrant
		otherUser := entity.NewRefreshToken("user-2", "", &entity.IssuedTokens{RefreshToken: "other-user-token", Scope: entity.MustParseScope("openid")})
		rtRepo := newMockRefreshTokenRepo(stolen, sameGrantSibling, otherGrantToken, otherUser)

		_, err := newUseCase(rtRepo).Dispatch(ctx, cmdFor("stolen-token"))
		assertErrCode(t, err, autherrors.InvalidRefreshToken)

		if rtRepo.tokens[entity.Hash("same-grant-sibling")].RevokedAt == nil {
			t.Error("replay must revoke all tokens in the same grant")
		}
		if rtRepo.tokens[entity.Hash("other-grant-token")].RevokedAt != nil {
			t.Error("replay must not touch the same user's other grant")
		}
		if rtRepo.tokens[entity.Hash("other-user-token")].RevokedAt != nil {
			t.Error("replay must not touch other users' tokens")
		}
	})

	t.Run("replayed legacy token (empty GrantID) — entire user family revoked", func(t *testing.T) {
		stolen := entity.NewRefreshToken("user-1", "", &entity.IssuedTokens{RefreshToken: "stolen-legacy-token", Scope: entity.MustParseScope("openid")})
		stolen.GrantID = "" // legacy: no grant ID
		stolen.RevokedAt = new(time.Now().Add(-time.Minute))
		sibling := entity.NewRefreshToken("user-1", "", &entity.IssuedTokens{RefreshToken: "sibling-token", Scope: entity.MustParseScope("openid")})
		otherUser := entity.NewRefreshToken("user-2", "", &entity.IssuedTokens{RefreshToken: "other-user-token", Scope: entity.MustParseScope("openid")})
		rtRepo := newMockRefreshTokenRepo(stolen, sibling, otherUser)

		_, err := newUseCase(rtRepo).Dispatch(ctx, cmdFor("stolen-legacy-token"))
		assertErrCode(t, err, autherrors.InvalidRefreshToken)

		if rtRepo.tokens[entity.Hash("sibling-token")].RevokedAt == nil {
			t.Error("legacy replay must revoke the user's entire token family")
		}
		if rtRepo.tokens[entity.Hash("other-user-token")].RevokedAt != nil {
			t.Error("legacy replay must not touch other users' tokens")
		}
	})

	t.Run("replayed token with GrantID — grant marker written in cache", func(t *testing.T) {
		grantID := entity.NewGrantID()
		stolen := entity.NewRefreshToken("user-1", "", &entity.IssuedTokens{RefreshToken: "stolen-grant-token", Scope: entity.MustParseScope("openid")})
		stolen.GrantID = grantID
		stolen.RevokedAt = new(time.Now().Add(-time.Minute))
		cache := newMockCache()
		mod := usecase.NewRegistry()
		mod.Register(RefreshTokenCommand{}, NewRefreshTokenUseCase(define.Dependencies{
			UoW:              &mockUoW{},
			JWTSvc:           &mockJwtService{accessToken: "new-access", refreshToken: "new-refresh"},
			UserRepo:         newMockRepo(newTestUser()),
			Cache:            cache,
			RefreshTokenRepo: newMockRefreshTokenRepo(stolen),
			GrantRepo:        newMockGrantRepo(),
			ClientRegistry:   newMockClientRegistry(newTestClient(t, "APP_ID", entity.ClientAuthNone)),
		}))
		_, err := mod.Dispatch(ctx, cmdFor("stolen-grant-token"))
		assertErrCode(t, err, autherrors.InvalidRefreshToken)
		markerKey := define.RevokedGrantKey(grantID)
		if _, ok := cache.items[markerKey]; !ok {
			t.Errorf("expected grant revocation marker %q in cache after replay, not found", markerKey)
		}
	})

	t.Run("replayed legacy token (empty GrantID) — no grant marker written", func(t *testing.T) {
		stolen := entity.NewRefreshToken("user-1", "", &entity.IssuedTokens{RefreshToken: "stolen-legacy-marker", Scope: entity.MustParseScope("openid")})
		stolen.GrantID = ""
		stolen.RevokedAt = new(time.Now().Add(-time.Minute))
		cache := newMockCache()
		mod := usecase.NewRegistry()
		mod.Register(RefreshTokenCommand{}, NewRefreshTokenUseCase(define.Dependencies{
			UoW:              &mockUoW{},
			JWTSvc:           &mockJwtService{accessToken: "new-access", refreshToken: "new-refresh"},
			UserRepo:         newMockRepo(newTestUser()),
			Cache:            cache,
			RefreshTokenRepo: newMockRefreshTokenRepo(stolen),
			GrantRepo:        newMockGrantRepo(),
			ClientRegistry:   newMockClientRegistry(newTestClient(t, "APP_ID", entity.ClientAuthNone)),
		}))
		_, err := mod.Dispatch(ctx, cmdFor("stolen-legacy-marker"))
		assertErrCode(t, err, autherrors.InvalidRefreshToken)
		if len(cache.items) != 0 {
			t.Errorf("expected no cache entries for legacy replay, got %d: %v", len(cache.items), cache.items)
		}
	})

	t.Run("expired token — family left intact", func(t *testing.T) {
		expired := entity.NewRefreshToken("user-1", "", &entity.IssuedTokens{RefreshToken: "expired-token", Scope: entity.MustParseScope("openid")})
		expired.ExpiresAt = time.Now().Add(-time.Minute)
		sibling := entity.NewRefreshToken("user-1", "", &entity.IssuedTokens{RefreshToken: "sibling-token", Scope: entity.MustParseScope("openid")})
		rtRepo := newMockRefreshTokenRepo(expired, sibling)

		_, err := newUseCase(rtRepo).Dispatch(ctx, cmdFor("expired-token"))
		assertErrCode(t, err, autherrors.InvalidRefreshToken)

		if rtRepo.tokens[entity.Hash("sibling-token")].RevokedAt != nil {
			t.Error("expiry is not evidence of theft; family must stay intact")
		}
	})

	t.Run("race loser (conditional revoke misses) — family left intact", func(t *testing.T) {
		active := entity.NewRefreshToken("user-1", "", &entity.IssuedTokens{RefreshToken: "racing-token", Scope: entity.MustParseScope("openid")})
		sibling := entity.NewRefreshToken("user-1", "", &entity.IssuedTokens{RefreshToken: "sibling-token", Scope: entity.MustParseScope("openid")})
		rtRepo := newMockRefreshTokenRepo(active, sibling)
		rtRepo.revokeByHashErr = coreerror.ErrNotFound // another request already rotated it

		_, err := newUseCase(rtRepo).Dispatch(ctx, cmdFor("racing-token"))
		assertErrCode(t, err, autherrors.InvalidRefreshToken)

		if rtRepo.tokens[entity.Hash("sibling-token")].RevokedAt != nil {
			t.Error("losing a rotation race is not a replay; family must stay intact")
		}
	})

	t.Run("replay revokes the grant before sweeping its rows", func(t *testing.T) {
		ops := &opsLog{}
		stolen := entity.NewRefreshToken("user-1", "", &entity.IssuedTokens{RefreshToken: "stolen-ordered", Scope: entity.MustParseScope("openid")})
		stolen.RevokedAt = new(time.Now().Add(-time.Minute))
		rtRepo := newMockRefreshTokenRepo(stolen)
		grantRepo := newMockGrantRepo()
		grant := entity.NewGrant("user-1", "")
		grant.ID = stolen.GrantID
		if err := grantRepo.Save(ctx, grant); err != nil {
			t.Fatalf("seeding grant: %v", err)
		}
		// Attached after seeding so the log covers only the call under test.
		rtRepo.ops = ops
		grantRepo.ops = ops

		mod := usecase.NewRegistry()
		mod.Register(RefreshTokenCommand{}, NewRefreshTokenUseCase(define.Dependencies{
			UoW:              &mockUoW{},
			JWTSvc:           &mockJwtService{accessToken: "new-access", refreshToken: "new-refresh"},
			UserRepo:         newMockRepo(newTestUser()),
			Cache:            newMockCache(),
			RefreshTokenRepo: rtRepo,
			GrantRepo:        grantRepo,
			ClientRegistry:   newMockClientRegistry(newTestClient(t, "APP_ID", entity.ClientAuthNone)),
		}))
		_, err := mod.Dispatch(ctx, cmdFor("stolen-ordered"))
		assertErrCode(t, err, autherrors.InvalidRefreshToken)

		if got := ops.all(); !slices.Equal(got, []string{"revoke_grant", "sweep_rows"}) {
			t.Errorf("call order = %v, want [revoke_grant sweep_rows] — the durable record must be written before the non-atomic sweep", got)
		}
		if stored := grantRepo.grants[stolen.GrantID]; stored == nil || stored.RevokedAt == nil {
			t.Error("replay must revoke the grant itself, not only its rows")
		}
	})
}

func TestRefreshTokenUseCase(t *testing.T) {
	ctx := context.Background()

	newValidRT := func() *entity.RefreshToken {
		return entity.NewRefreshToken("user-1", "", &entity.IssuedTokens{RefreshToken: "valid-refresh-token", Scope: entity.MustParseScope("openid email profile phone")})
	}

	tests := []struct {
		name             string
		cmd              *RefreshTokenCommand
		jwt              *mockJwtService
		repo             *mockUserRepo
		rtRepo           *mockRefreshTokenRepo
		wantErrCode      coreerror.ErrCode
		wantToken        string
		wantIDTokenEmpty bool
	}{
		{
			name: "success",
			cmd: &RefreshTokenCommand{
				GrantType:    "refresh_token",
				ClientID:     "APP_ID",
				RefreshToken: "valid-refresh-token",
				ExpireSecs:   new(600),
			},
			jwt:       &mockJwtService{accessToken: "new-access", refreshToken: "new-refresh"},
			repo:      newMockRepo(newTestUser()),
			rtRepo:    newMockRefreshTokenRepo(newValidRT()),
			wantToken: "new-access",
		},
		{
			name: "token bound to the presenting client — rotated",
			cmd: &RefreshTokenCommand{
				GrantType:    "refresh_token",
				ClientID:     "APP_ID",
				RefreshToken: "valid-refresh-token",
			},
			jwt:       &mockJwtService{accessToken: "new-access", refreshToken: "new-refresh"},
			repo:      newMockRepo(newTestUser()),
			rtRepo:    newMockRefreshTokenRepo(entity.NewRefreshToken("user-1", "APP_ID", &entity.IssuedTokens{RefreshToken: "valid-refresh-token", Scope: entity.MustParseScope("openid")})),
			wantToken: "new-access",
		},
		{
			name: "token bound to another client — rejected (finding: refresh tokens client-bound)",
			cmd: &RefreshTokenCommand{
				GrantType:    "refresh_token",
				ClientID:     "APP_ID",
				RefreshToken: "valid-refresh-token",
			},
			jwt:         &mockJwtService{},
			repo:        newMockRepo(newTestUser()),
			rtRepo:      newMockRefreshTokenRepo(entity.NewRefreshToken("user-1", "client-123", &entity.IssuedTokens{RefreshToken: "valid-refresh-token", Scope: entity.MustParseScope("openid")})),
			wantErrCode: autherrors.InvalidRefreshToken,
		},
		{
			name: "token not found",
			cmd: &RefreshTokenCommand{
				GrantType:    "refresh_token",
				ClientID:     "APP_ID",
				RefreshToken: "unknown-token",
			},
			jwt:         &mockJwtService{},
			repo:        newMockRepo(newTestUser()),
			rtRepo:      newMockRefreshTokenRepo(),
			wantErrCode: autherrors.InvalidRefreshToken,
		},
		{
			name:        "missing grant_type — validation failure",
			cmd:         &RefreshTokenCommand{ClientID: "APP_ID", RefreshToken: "valid-refresh-token"},
			jwt:         &mockJwtService{},
			repo:        newMockRepo(),
			rtRepo:      newMockRefreshTokenRepo(),
			wantErrCode: autherrors.InvalidArguments,
		},
		{
			name:        "missing client_id — invalid_client (no client on either channel)",
			cmd:         &RefreshTokenCommand{GrantType: "refresh_token", RefreshToken: "valid-refresh-token"},
			jwt:         &mockJwtService{},
			repo:        newMockRepo(),
			rtRepo:      newMockRefreshTokenRepo(),
			wantErrCode: autherrors.InvalidClient,
		},
		{
			name:        "missing refresh_token — validation failure",
			cmd:         &RefreshTokenCommand{GrantType: "refresh_token", ClientID: "APP_ID"},
			jwt:         &mockJwtService{},
			repo:        newMockRepo(),
			rtRepo:      newMockRefreshTokenRepo(),
			wantErrCode: autherrors.InvalidArguments,
		},
		{
			name:        "negative expire_secs — validation failure",
			cmd:         &RefreshTokenCommand{GrantType: "refresh_token", ClientID: "APP_ID", RefreshToken: "valid-refresh-token", ExpireSecs: new(-1)},
			jwt:         &mockJwtService{},
			repo:        newMockRepo(),
			rtRepo:      newMockRefreshTokenRepo(),
			wantErrCode: autherrors.InvalidArguments,
		},
		{
			name: "genAccessToken fails",
			cmd: &RefreshTokenCommand{
				GrantType:    "refresh_token",
				ClientID:     "APP_ID",
				RefreshToken: "valid-refresh-token",
			},
			jwt:         &mockJwtService{accessErr: errors.New("sign error")},
			repo:        newMockRepo(newTestUser()),
			rtRepo:      newMockRefreshTokenRepo(newValidRT()),
			wantErrCode: autherrors.GenTokenFailed,
		},
		{
			name: "genRefreshToken fails",
			cmd: &RefreshTokenCommand{
				GrantType:    "refresh_token",
				ClientID:     "APP_ID",
				RefreshToken: "valid-refresh-token",
			},
			jwt:         &mockJwtService{accessToken: "new-access", refreshErr: errors.New("rand error")},
			repo:        newMockRepo(newTestUser()),
			rtRepo:      newMockRefreshTokenRepo(newValidRT()),
			wantErrCode: autherrors.GenRefreshTokenFailed,
		},
		{
			name: "RevokeByTokenHash fails — GenRefreshTokenFailed",
			cmd: &RefreshTokenCommand{
				GrantType:    "refresh_token",
				ClientID:     "APP_ID",
				RefreshToken: "valid-refresh-token",
			},
			jwt:         &mockJwtService{accessToken: "new-access", refreshToken: "new-refresh"},
			repo:        newMockRepo(newTestUser()),
			rtRepo:      &mockRefreshTokenRepo{tokens: map[string]*entity.RefreshToken{entity.Hash("valid-refresh-token"): newValidRT()}, revokeByHashErr: errors.New("db error")},
			wantErrCode: autherrors.GenRefreshTokenFailed,
		},
		{
			name: "Save fails — GenRefreshTokenFailed",
			cmd: &RefreshTokenCommand{
				GrantType:    "refresh_token",
				ClientID:     "APP_ID",
				RefreshToken: "valid-refresh-token",
			},
			jwt:         &mockJwtService{accessToken: "new-access", refreshToken: "new-refresh"},
			repo:        newMockRepo(newTestUser()),
			rtRepo:      &mockRefreshTokenRepo{tokens: map[string]*entity.RefreshToken{entity.Hash("valid-refresh-token"): newValidRT()}, saveErr: errors.New("db error")},
			wantErrCode: autherrors.GenRefreshTokenFailed,
		},
		{
			name: "user not found — invalid refresh token",
			cmd: &RefreshTokenCommand{
				GrantType:    "refresh_token",
				ClientID:     "APP_ID",
				RefreshToken: "valid-refresh-token",
			},
			jwt:         &mockJwtService{},
			repo:        newMockRepo(), // no users
			rtRepo:      newMockRefreshTokenRepo(newValidRT()),
			wantErrCode: autherrors.InvalidRefreshToken,
		},
		{
			name: "revoked token — invalid refresh token error",
			cmd: &RefreshTokenCommand{
				GrantType:    "refresh_token",
				ClientID:     "APP_ID",
				RefreshToken: "valid-refresh-token",
			},
			jwt:  &mockJwtService{},
			repo: newMockRepo(newTestUser()),
			rtRepo: func() *mockRefreshTokenRepo {
				rt := newValidRT()
				rt.RevokedAt = new(time.Now())
				return newMockRefreshTokenRepo(rt)
			}(),
			wantErrCode: autherrors.InvalidRefreshToken,
		},
		{
			name: "expired token — invalid refresh token error",
			cmd: &RefreshTokenCommand{
				GrantType:    "refresh_token",
				ClientID:     "APP_ID",
				RefreshToken: "valid-refresh-token",
			},
			jwt:  &mockJwtService{},
			repo: newMockRepo(newTestUser()),
			rtRepo: func() *mockRefreshTokenRepo {
				rt := newValidRT()
				rt.ExpiresAt = time.Now().Add(-1 * time.Minute)
				return newMockRefreshTokenRepo(rt)
			}(),
			wantErrCode: autherrors.InvalidRefreshToken,
		},
		{
			name: "genIDToken fails",
			cmd: &RefreshTokenCommand{
				GrantType:    "refresh_token",
				ClientID:     "APP_ID",
				RefreshToken: "valid-refresh-token",
			},
			jwt:         &mockJwtService{accessToken: "new-access", refreshToken: "new-refresh", idTokenErr: errors.New("sign error")},
			repo:        newMockRepo(newTestUser()),
			rtRepo:      newMockRefreshTokenRepo(newValidRT()),
			wantErrCode: autherrors.GenTokenFailed,
		},
		{
			// AuthenticatedAt < cutoff but CreatedAt > cutoff (post-rotation timestamp).
			// The check must use AuthenticatedAt; using CreatedAt would wrongly allow this token.
			name: "AuthenticatedAt before SessionsInvalidatedAt — rejected even if CreatedAt is after",
			cmd: &RefreshTokenCommand{
				GrantType:    "refresh_token",
				ClientID:     "APP_ID",
				RefreshToken: "valid-refresh-token",
			},
			jwt: &mockJwtService{},
			repo: func() *mockUserRepo {
				u := newTestUser()
				cutoff := time.Now().Add(-30 * time.Minute)
				u.SessionsInvalidatedAt = &cutoff
				return newMockRepo(u)
			}(),
			rtRepo: func() *mockRefreshTokenRepo {
				rt := newValidRT()
				rt.AuthenticatedAt = time.Now().Add(-time.Hour) // original auth before cutoff
				// rt.CreatedAt remains time.Now() — after the cutoff
				return newMockRefreshTokenRepo(rt)
			}(),
			wantErrCode: autherrors.InvalidRefreshToken,
		},
		{
			name: "unknown client — invalid_client",
			cmd: &RefreshTokenCommand{
				GrantType:    "refresh_token",
				ClientID:     "ghost-client",
				RefreshToken: "valid-refresh-token",
			},
			jwt:         &mockJwtService{},
			repo:        newMockRepo(newTestUser()),
			rtRepo:      newMockRefreshTokenRepo(newValidRT()),
			wantErrCode: autherrors.InvalidClient,
		},
		{
			name: "confidential client with wrong secret — invalid_client",
			cmd: &RefreshTokenCommand{
				GrantType:    "refresh_token",
				ClientID:     "client-123",
				ClientSecret: "wrong-secret",
				RefreshToken: "valid-refresh-token",
			},
			jwt:         &mockJwtService{},
			repo:        newMockRepo(newTestUser()),
			rtRepo:      newMockRefreshTokenRepo(newValidRT()),
			wantErrCode: autherrors.InvalidClient,
		},
		{
			name: "confidential client with correct secret — rotated",
			cmd: &RefreshTokenCommand{
				GrantType:    "refresh_token",
				ClientID:     "client-123",
				ClientSecret: testClientSecret,
				RefreshToken: "valid-refresh-token",
			},
			jwt:       &mockJwtService{accessToken: "conf-access", refreshToken: "conf-refresh"},
			repo:      newMockRepo(newTestUser()),
			rtRepo:    newMockRefreshTokenRepo(newValidRT()),
			wantToken: "conf-access",
		},
		{
			name: "client not allowed to use refresh_token grant — invalid_client",
			cmd: &RefreshTokenCommand{
				GrantType:    "refresh_token",
				ClientID:     "password-only-client",
				ClientSecret: testClientSecret,
				RefreshToken: "valid-refresh-token",
			},
			jwt:         &mockJwtService{},
			repo:        newMockRepo(newTestUser()),
			rtRepo:      newMockRefreshTokenRepo(newValidRT()),
			wantErrCode: autherrors.InvalidClient,
		},
		{
			name: "scope without openid — id_token omitted",
			cmd: &RefreshTokenCommand{
				GrantType:    "refresh_token",
				ClientID:     "APP_ID",
				RefreshToken: "valid-refresh-token",
			},
			jwt:  &mockJwtService{accessToken: "new-access", refreshToken: "new-refresh"},
			repo: newMockRepo(newTestUser()),
			rtRepo: newMockRefreshTokenRepo(entity.NewRefreshToken(
				"user-1", "",
				&entity.IssuedTokens{RefreshToken: "valid-refresh-token", Scope: entity.MustParseScope("email profile")},
			)),
			wantToken:        "new-access",
			wantIDTokenEmpty: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mod := usecase.NewRegistry()
			mod.Register(RefreshTokenCommand{}, NewRefreshTokenUseCase(define.Dependencies{
				UoW:              &mockUoW{},
				JWTSvc:           tc.jwt,
				UserRepo:         tc.repo,
				RefreshTokenRepo: tc.rtRepo,
				GrantRepo:        newMockGrantRepo(),
				ClientRegistry: newMockClientRegistry(
					newTestClient(t, "APP_ID", entity.ClientAuthNone),
					newTestClient(t, "client-123", entity.ClientAuthSecretPost),
					newTestClient(t, "password-only-client", entity.ClientAuthSecretPost, entity.GrantPassword),
				),
			}))
			result, err := mod.Dispatch(ctx, tc.cmd)

			if tc.wantErrCode != 0 {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if e, ok := err.(interface{ Code() coreerror.ErrCode }); !ok || e.Code() != tc.wantErrCode {
					t.Fatalf("got err_code %v, want %d", err, tc.wantErrCode)
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			resp := result.(*define.TokenResponse)
			if resp.AccessToken != tc.wantToken {
				t.Fatalf("access_token = %q, want %q", resp.AccessToken, tc.wantToken)
			}
			if resp.RefreshToken == "" {
				t.Fatal("refresh_token should not be empty")
			}
			if tc.wantIDTokenEmpty {
				if resp.IDToken != "" {
					t.Errorf("id_token = %q, want empty", resp.IDToken)
				}
			} else {
				if resp.IDToken == "" {
					t.Fatal("id_token should not be empty")
				}
			}

			// rotation: old token revoked, new token persisted, custom expire_secs honoured
			oldHash := entity.Hash("valid-refresh-token")
			if rt, _ := tc.rtRepo.FindByTokenHash(ctx, oldHash); rt == nil || rt.RevokedAt == nil {
				t.Error("old refresh token should be revoked after rotation")
			}
			newHash := entity.Hash(resp.RefreshToken)
			if _, _ = tc.rtRepo.FindByTokenHash(ctx, newHash); tc.rtRepo.tokens[newHash] == nil {
				t.Error("new refresh token should be persisted after rotation")
			}
			if tc.cmd.ExpireSecs != nil && tc.jwt.capturedAccessExpireSecs != *tc.cmd.ExpireSecs {
				t.Errorf("capturedAccessExpireSecs = %d, want %d", tc.jwt.capturedAccessExpireSecs, *tc.cmd.ExpireSecs)
			}
		})
	}
}

// TestRefreshTokenUseCase_UoWError exercises the error-wrapping logic added to
// updateRefreshToken: a bare (non-ErrorStruct) error from the UnitOfWork (e.g.
// session/transaction start failure) must be wrapped into GenRefreshTokenFailed,
// while an ErrorStruct already produced inside the closure must pass through
// without an additional layer of wrapping.
func TestRefreshTokenUseCase_UoWError(t *testing.T) {
	ctx := context.Background()

	newValidRT := func() *entity.RefreshToken {
		return entity.NewRefreshToken("user-1", "", &entity.IssuedTokens{RefreshToken: "valid-refresh-token", Scope: entity.MustParseScope("openid")})
	}

	newUseCase := func(uow interface {
		Do(context.Context, func(context.Context) (any, error)) (any, error)
	}, rtRepo *mockRefreshTokenRepo) *usecase.Registry {
		mod := usecase.NewRegistry()
		mod.Register(RefreshTokenCommand{}, NewRefreshTokenUseCase(define.Dependencies{
			UoW:              uow,
			JWTSvc:           &mockJwtService{accessToken: "new-access", refreshToken: "new-refresh"},
			UserRepo:         newMockRepo(newTestUser()),
			RefreshTokenRepo: rtRepo,
			GrantRepo:        newMockGrantRepo(),
			ClientRegistry:   newMockClientRegistry(newTestClient(t, "APP_ID", entity.ClientAuthNone)),
		}))
		return mod
	}

	cmd := &RefreshTokenCommand{GrantType: "refresh_token", ClientID: "APP_ID", RefreshToken: "valid-refresh-token"}

	t.Run("bare UoW error wrapped to GenRefreshTokenFailed", func(t *testing.T) {
		_, err := newUseCase(
			&failingUoW{err: fmt.Errorf("session start failed")},
			newMockRefreshTokenRepo(newValidRT()),
		).Dispatch(ctx, cmd)
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		es, ok := err.(*coreerror.ErrorStruct)
		if !ok {
			t.Fatalf("expected *coreerror.ErrorStruct, got %T: %v", err, err)
		}
		if es.Code() != autherrors.GenRefreshTokenFailed {
			t.Fatalf("got err_code %d, want %d", es.Code(), autherrors.GenRefreshTokenFailed)
		}
	})

	t.Run("ErrorStruct from inside closure passes through unwrapped", func(t *testing.T) {
		// RevokeByTokenHash returns a non-ErrNotFound error inside the closure;
		// the use case wraps it with NewErrGenRefreshTokenFailed (an ErrorStruct).
		// The post-Do guard must return that ErrorStruct as-is without re-wrapping.
		revokeByHashErr := errors.New("db error")
		rtRepo := newMockRefreshTokenRepo(newValidRT())
		rtRepo.revokeByHashErr = revokeByHashErr
		_, err := newUseCase(&mockUoW{}, rtRepo).Dispatch(ctx, cmd)
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		es, ok := err.(*coreerror.ErrorStruct)
		if !ok {
			t.Fatalf("expected *coreerror.ErrorStruct, got %T: %v", err, err)
		}
		if es.Code() != autherrors.GenRefreshTokenFailed {
			t.Fatalf("got err_code %d, want %d (GenRefreshTokenFailed)", es.Code(), autherrors.GenRefreshTokenFailed)
		}
		if cause := errors.Unwrap(es); cause != revokeByHashErr {
			t.Fatalf("expected unwrapped cause == revokeByHashErr sentinel, got %v", cause)
		}
	})

	t.Run("ErrNotFound from closure becomes InvalidRefreshToken (not re-wrapped)", func(t *testing.T) {
		rtRepo := newMockRefreshTokenRepo(newValidRT())
		rtRepo.revokeByHashErr = coreerror.ErrNotFound
		_, err := newUseCase(&mockUoW{}, rtRepo).Dispatch(ctx, cmd)
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		es, ok := err.(*coreerror.ErrorStruct)
		if !ok {
			t.Fatalf("expected *coreerror.ErrorStruct, got %T: %v", err, err)
		}
		if es.Code() != autherrors.InvalidRefreshToken {
			t.Fatalf("got err_code %d, want %d (InvalidRefreshToken)", es.Code(), autherrors.InvalidRefreshToken)
		}
	})
}
