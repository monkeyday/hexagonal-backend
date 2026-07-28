package command

import (
	"context"
	"errors"
	"time"

	coreerror "sc/core/error"
	coreuow "sc/core/uow"
	"sc/core/usecase"
	"sc/modules/auth/application/define"
	domainService "sc/modules/auth/application/service"
	"sc/modules/auth/domain/entity"
	autherrors "sc/modules/auth/errors"
	"sc/modules/auth/port"

	"github.com/rs/zerolog/log"
)

type RefreshTokenCommand struct {
	GrantType         string `form:"grant_type" json:"grant_type" validate:"required"`
	ClientID          string `form:"client_id" json:"client_id"`
	ClientSecret      string `form:"client_secret" json:"client_secret"`
	BasicClientID     string `ctx:"basic_client_id"`
	BasicClientSecret string `ctx:"basic_client_secret"`
	RefreshToken      string `form:"refresh_token" json:"refresh_token" cookie:"refresh_token" validate:"required"`
	ExpireSecs        *int   `form:"expire_secs" json:"expire_secs" validate:"omitempty,gt=0"`
}

type RefreshTokenUseCase struct {
	uow                  coreuow.UnitOfWork
	revocationCache      *domainService.RevocationCache
	userRepo             port.UserRepository
	refreshTokenRepo     port.RefreshTokenRepository
	grantRepo            port.GrantRepository
	tokenIssuanceService *domainService.TokenIssuanceService
	clientAuthenticator  *domainService.ClientAuthenticator
}

func NewRefreshTokenUseCase(deps define.Dependencies) usecase.UseCase {
	return &RefreshTokenUseCase{
		uow:                  deps.UoW,
		revocationCache:      domainService.NewRevocationCache(deps.Cache),
		userRepo:             deps.UserRepo,
		refreshTokenRepo:     deps.RefreshTokenRepo,
		grantRepo:            deps.GrantRepo,
		tokenIssuanceService: domainService.NewTokenIssuanceService(deps.JWTSvc),
		clientAuthenticator:  domainService.NewClientAuthenticator(deps.ClientRegistry),
	}
}

// writeRevokedGrantMarker caches a grant-revocation marker so that stateless
// sibling access tokens issued under the same grant stop verifying.
// Errors are logged but not propagated — revocation of the refresh-token family
// already happened; the marker is best-effort in the replay path.
func (uc *RefreshTokenUseCase) writeRevokedGrantMarker(ctx context.Context, grantID entity.GrantID) {
	if uc.revocationCache == nil {
		return
	}
	if err := uc.revocationCache.MarkGrantRevoked(ctx, grantID); err != nil {
		log.Error().Err(err).Str("grant_id", string(grantID)).Msg("revoked_grant: cache set failed after replay")
	}
}

// revokeGrant marks the grant itself dead ahead of the row sweep, so the fact
// survives a rotation that commits mid-sweep and outlives the cache marker's
// TTL (grant-linkage.md §10). ErrNotFound means the grant predates this record
// or a concurrent revocation won — neither is an error here. Best-effort like
// the sweep it precedes: the caller is already returning a replay rejection.
func (uc *RefreshTokenUseCase) revokeGrant(ctx context.Context, grantID entity.GrantID) {
	if err := uc.grantRepo.Revoke(ctx, grantID, time.Now()); err != nil && !errors.Is(err, coreerror.ErrNotFound) {
		log.Error().Err(err).Str("grant_id", string(grantID)).Msg("failed to revoke grant after replay")
	}
}

func (uc *RefreshTokenUseCase) Execute(ctx context.Context, cmd any) (any, error) {
	c := cmd.(*RefreshTokenCommand)

	client, err := uc.clientAuthenticator.Authenticate(ctx, domainService.ClientCredentials{
		ClientID:      c.ClientID,
		FormSecret:    c.ClientSecret,
		BasicClientID: c.BasicClientID,
		BasicSecret:   c.BasicClientSecret,
	})
	if err != nil {
		return nil, autherrors.NewErrInvalidClient()
	}
	if !client.AllowsGrant(entity.GrantRefreshToken) {
		return nil, autherrors.NewErrInvalidClient()
	}

	rt, err := uc.findActiveRefreshToken(ctx, c.RefreshToken)
	if err != nil {
		return nil, err
	}

	// A refresh token may only be rotated by the client it was issued to
	// (RFC 6749 §6); a mismatch suggests a token stolen from another client.
	if !rt.IssuedTo(client.ID) {
		return nil, autherrors.NewErrInvalidRefreshToken()
	}

	user, err := uc.userRepo.FindByID(ctx, rt.UserID)
	if err != nil || user == nil {
		return nil, autherrors.NewErrInvalidRefreshToken()
	}

	if user.SessionsInvalidatedAt != nil && !rt.AuthenticatedAt.After(*user.SessionsInvalidatedAt) {
		return nil, autherrors.NewErrInvalidRefreshToken()
	}

	expireSecs := define.ResolveExpirySecs(c.ExpireSecs)

	tokens, err := uc.tokenIssuanceService.IssueTokens(domainService.IssueTokensArgs{
		User:            user,
		ClientID:        client.ID,
		Scope:           rt.Scope,
		ExpireSecs:      expireSecs,
		ExistingGrantID: rt.GrantID,
	})
	if err != nil {
		return nil, err
	}

	// Built here rather than inside the transaction so its expiry is fixed before
	// any grant is written: both the freshly minted grant below and the existing
	// one extended inside updateRefreshToken are aligned to this exact value, and
	// a transaction retry reuses it instead of stamping a later one.
	newRT := rt.Rotate(user.ID, tokens)

	if tokens.NewGrant != nil {
		tokens.NewGrant.ExtendToCover(newRT.ExpiresAt)
		if err := uc.grantRepo.Save(ctx, tokens.NewGrant); err != nil {
			return nil, autherrors.NewErrGenRefreshTokenFailed(err)
		}
	}

	if err := uc.updateRefreshToken(ctx, rt, newRT); err != nil {
		return nil, err
	}

	res := &define.TokenResponse{}
	res.FromEntity(tokens, expireSecs)
	return res, nil
}

// findActiveRefreshToken loads the presented token and enforces reuse
// detection: a revoked token being presented again means it was already
// rotated once — assume theft and revoke the user's whole token family.
// Expired tokens are rejected without consequences; expiry is not evidence
// of theft. Runs outside the rotation transaction on purpose: the family
// revocation must survive the request failing.
func (uc *RefreshTokenUseCase) findActiveRefreshToken(ctx context.Context, raw string) (*entity.RefreshToken, error) {
	rt, err := uc.refreshTokenRepo.FindByTokenHash(ctx, entity.Hash(raw))
	if err != nil || rt == nil {
		return nil, autherrors.NewErrInvalidRefreshToken()
	}
	if rt.RevokedAt != nil {
		if rt.GrantID != "" {
			log.Warn().Str("grant_id", string(rt.GrantID)).Str("user_id", string(rt.UserID)).Msg("refresh token replay detected; revoking all tokens for grant")
			uc.revokeGrant(ctx, rt.GrantID)
			if err := uc.refreshTokenRepo.RevokeAllForGrant(ctx, rt.GrantID); err != nil {
				log.Error().Err(err).Str("grant_id", string(rt.GrantID)).Msg("failed to revoke token family after replay")
			}
			uc.writeRevokedGrantMarker(ctx, rt.GrantID)
		} else {
			// Legacy fallback: tokens issued before grant linkage carry no GrantID; revoke by user.
			log.Warn().Str("user_id", string(rt.UserID)).Msg("refresh token replay detected; revoking all tokens for user")
			if err := uc.refreshTokenRepo.RevokeAllForUser(ctx, rt.UserID); err != nil {
				log.Error().Err(err).Str("user_id", string(rt.UserID)).Msg("failed to revoke token family after replay")
			}
		}
		return nil, autherrors.NewErrInvalidRefreshToken()
	}
	if !rt.IsValid() {
		return nil, autherrors.NewErrInvalidRefreshToken()
	}
	return rt, nil
}

// checkAndExtendGrant rejects a rotation whose grant is revoked or expired, and
// otherwise pushes the grant's expiry out so it outlives the refresh token being
// issued. Must be called inside the rotation transaction.
//
// An empty grantID, or a grant that no longer exists, fails open: chains
// authenticated before grants were persisted have nothing to check, and the
// rotation falls through to the checks that already exist. PR9 flips this to
// fail-closed once the TTL window has elapsed (grant-linkage.md §10).
func (uc *RefreshTokenUseCase) checkAndExtendGrant(ctx context.Context, grantID entity.GrantID, tokenExpiry time.Time) error {
	if grantID == "" {
		return nil
	}
	grant, err := uc.grantRepo.FindByID(ctx, grantID)
	if err != nil {
		if errors.Is(err, coreerror.ErrNotFound) {
			return nil
		}
		return autherrors.NewErrGenRefreshTokenFailed(err)
	}
	if !grant.IsValid() {
		return autherrors.NewErrInvalidRefreshToken()
	}
	grant.ExtendToCover(tokenExpiry)
	if err := uc.grantRepo.Save(ctx, grant); err != nil {
		return autherrors.NewErrGenRefreshTokenFailed(err)
	}
	return nil
}

// updateRefreshToken rotates the chain inside one transaction. The grant check
// goes first and inside it on purpose: extending ExpiresAt writes the grant
// document, so a concurrent Revoke of the same grant raises a write conflict,
// the transaction retries, and the retry sees the revocation and rejects — the
// grant document is the serialization point a multi-row sweep cannot be
// (grant-linkage.md §10).
func (uc *RefreshTokenUseCase) updateRefreshToken(ctx context.Context, oldRT, newRT *entity.RefreshToken) error {
	_, err := uc.uow.Do(ctx, func(ctx context.Context) (any, error) {
		if err := uc.checkAndExtendGrant(ctx, oldRT.GrantID, newRT.ExpiresAt); err != nil {
			return nil, err
		}
		if err := uc.refreshTokenRepo.RevokeByTokenHash(ctx, oldRT.TokenHash); err != nil {
			if errors.Is(err, coreerror.ErrNotFound) {
				return nil, autherrors.NewErrInvalidRefreshToken()
			}
			return nil, autherrors.NewErrGenRefreshTokenFailed(err)
		}
		if err := uc.refreshTokenRepo.Save(ctx, newRT); err != nil {
			return nil, autherrors.NewErrGenRefreshTokenFailed(err)
		}
		return nil, nil
	})
	if err != nil {
		if _, ok := err.(*coreerror.ErrorStruct); ok {
			return err
		}
		return autherrors.NewErrGenRefreshTokenFailed(err)
	}
	return nil
}
