package adapter

import (
	"context"
	"errors"
	"testing"
	"time"

	coreerror "sc/core/error"
	"sc/modules/auth/domain/entity"
	"sc/modules/auth/port"
)

// runRefreshTokenContract exercises the behaviour every RefreshTokenRepository
// implementation must share. newRepo returns a fresh, empty repository for each
// subtest so the drivers (file, mongo) stay isolated. This is the parity
// harness: file and mongo run the identical assertions.
func runRefreshTokenContract(t *testing.T, newRepo func(t *testing.T) port.RefreshTokenRepository) {
	ctx := context.Background()

	t.Run("Save then FindByTokenHash round-trips the token", func(t *testing.T) {
		repo := newRepo(t)
		rt := newTestRefreshToken("rt-1", "user-1", "hash-abc", 30*24*time.Hour)
		if err := repo.Save(ctx, rt); err != nil {
			t.Fatalf("Save: %v", err)
		}
		found, err := repo.FindByTokenHash(ctx, rt.TokenHash)
		if err != nil {
			t.Fatalf("FindByTokenHash: %v", err)
		}
		assertRefreshTokenEqual(t, rt, found)
	})

	t.Run("Save is an upsert on ID", func(t *testing.T) {
		repo := newRepo(t)
		rt := newTestRefreshToken("rt-1", "user-1", "hash-abc", 30*24*time.Hour)
		if err := repo.Save(ctx, rt); err != nil {
			t.Fatalf("Save: %v", err)
		}
		revokedAt := time.Now().UTC().Truncate(time.Millisecond)
		rt.RevokedAt = &revokedAt
		if err := repo.Save(ctx, rt); err != nil {
			t.Fatalf("Save (update): %v", err)
		}
		found, err := repo.FindByTokenHash(ctx, rt.TokenHash)
		if err != nil {
			t.Fatalf("FindByTokenHash: %v", err)
		}
		if found.RevokedAt == nil {
			t.Error("expected RevokedAt to persist after re-Save")
		}
	})

	t.Run("FindByTokenHash not found returns ErrNotFound", func(t *testing.T) {
		repo := newRepo(t)
		_, err := repo.FindByTokenHash(ctx, "nonexistent-hash")
		if !errors.Is(err, coreerror.ErrNotFound) {
			t.Errorf("expected ErrNotFound, got %v", err)
		}
	})

	t.Run("RevokeByTokenHash revokes an active token", func(t *testing.T) {
		repo := newRepo(t)
		rt := newTestRefreshToken("rt-1", "user-1", "hash-active", 30*24*time.Hour)
		if err := repo.Save(ctx, rt); err != nil {
			t.Fatalf("Save: %v", err)
		}
		if err := repo.RevokeByTokenHash(ctx, rt.TokenHash); err != nil {
			t.Fatalf("RevokeByTokenHash: %v", err)
		}
		found, err := repo.FindByTokenHash(ctx, rt.TokenHash)
		if err != nil {
			t.Fatalf("FindByTokenHash: %v", err)
		}
		if found.RevokedAt == nil {
			t.Error("RevokedAt should be set after revocation")
		}
	})

	t.Run("RevokeByTokenHash on already-revoked returns ErrNotFound", func(t *testing.T) {
		repo := newRepo(t)
		rt := newTestRefreshToken("rt-1", "user-1", "hash-revoked", 30*24*time.Hour)
		now := time.Now().UTC().Truncate(time.Millisecond)
		rt.RevokedAt = &now
		if err := repo.Save(ctx, rt); err != nil {
			t.Fatalf("Save: %v", err)
		}
		if err := repo.RevokeByTokenHash(ctx, rt.TokenHash); !errors.Is(err, coreerror.ErrNotFound) {
			t.Errorf("expected ErrNotFound, got %v", err)
		}
	})

	t.Run("RevokeByTokenHash on expired token returns ErrNotFound", func(t *testing.T) {
		repo := newRepo(t)
		rt := newTestRefreshToken("rt-1", "user-1", "hash-expired", -time.Hour)
		if err := repo.Save(ctx, rt); err != nil {
			t.Fatalf("Save: %v", err)
		}
		if err := repo.RevokeByTokenHash(ctx, rt.TokenHash); !errors.Is(err, coreerror.ErrNotFound) {
			t.Errorf("expected ErrNotFound, got %v", err)
		}
	})

	t.Run("RevokeByTokenHash on nonexistent returns ErrNotFound", func(t *testing.T) {
		repo := newRepo(t)
		if err := repo.RevokeByTokenHash(ctx, "does-not-exist"); !errors.Is(err, coreerror.ErrNotFound) {
			t.Errorf("expected ErrNotFound, got %v", err)
		}
	})

	t.Run("RevokeAllForUser revokes only the target user's active tokens", func(t *testing.T) {
		repo := newRepo(t)
		userA := entity.UserID("user-a")
		userB := entity.UserID("user-b")

		rtA1 := newTestRefreshToken("rt-a1", string(userA), "hash-a1", 30*24*time.Hour)
		rtA2 := newTestRefreshToken("rt-a2", string(userA), "hash-a2", 30*24*time.Hour)
		rtARevoked := newTestRefreshToken("rt-a3", string(userA), "hash-a3", 30*24*time.Hour)
		revokedAt := time.Now().UTC().Truncate(time.Millisecond)
		rtARevoked.RevokedAt = &revokedAt
		rtB := newTestRefreshToken("rt-b1", string(userB), "hash-b1", 30*24*time.Hour)

		for _, rt := range []*entity.RefreshToken{rtA1, rtA2, rtARevoked, rtB} {
			if err := repo.Save(ctx, rt); err != nil {
				t.Fatalf("Save %q: %v", rt.ID, err)
			}
		}

		if err := repo.RevokeAllForUser(ctx, userA); err != nil {
			t.Fatalf("RevokeAllForUser: %v", err)
		}

		for _, hash := range []string{rtA1.TokenHash, rtA2.TokenHash} {
			found, err := repo.FindByTokenHash(ctx, hash)
			if err != nil {
				t.Fatalf("FindByTokenHash(%q): %v", hash, err)
			}
			if found.RevokedAt == nil {
				t.Errorf("token %q should be revoked after RevokeAllForUser", hash)
			}
		}

		foundB, err := repo.FindByTokenHash(ctx, rtB.TokenHash)
		if err != nil {
			t.Fatalf("FindByTokenHash(userB): %v", err)
		}
		if foundB.RevokedAt != nil {
			t.Error("userB's token should not be revoked")
		}
	})
}
