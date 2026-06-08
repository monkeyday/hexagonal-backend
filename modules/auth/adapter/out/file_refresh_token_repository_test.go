package adapter

import (
	"context"
	"errors"
	"testing"
	"time"

	coreerror "sc/core/error"
	filerepo "sc/infrastructure/repository/file"
	"sc/modules/auth/domain/entity"
)

func newRTFileStore(t *testing.T) *filerepo.FileStore {
	t.Helper()
	store, err := filerepo.NewFileStore(t.TempDir(), "refresh_tokens.json")
	if err != nil {
		t.Fatalf("NewFileStore: %v", err)
	}
	return store
}

func newTestRefreshToken(id, userID, tokenHash string, expiresIn time.Duration) *entity.RefreshToken {
	now := time.Now().Round(0)
	return &entity.RefreshToken{
		ID:              id,
		UserID:          entity.UserID(userID),
		TokenHash:       tokenHash,
		Scope:           entity.MustParseScope("openid email"),
		DeviceID:        "device-1",
		AuthenticatedAt: now,
		CreatedAt:       now,
		ExpiresAt:       now.Add(expiresIn),
	}
}

func assertRefreshTokenEqual(t *testing.T, want, got *entity.RefreshToken) {
	t.Helper()
	if got.ID != want.ID {
		t.Errorf("ID: got %q, want %q", got.ID, want.ID)
	}
	if got.UserID != want.UserID {
		t.Errorf("UserID: got %q, want %q", got.UserID, want.UserID)
	}
	if got.TokenHash != want.TokenHash {
		t.Errorf("TokenHash: got %q, want %q", got.TokenHash, want.TokenHash)
	}
	if got.Scope.String() != want.Scope.String() {
		t.Errorf("Scope: got %q, want %q", got.Scope.String(), want.Scope.String())
	}
	if got.DeviceID != want.DeviceID {
		t.Errorf("DeviceID: got %q, want %q", got.DeviceID, want.DeviceID)
	}
	if !got.AuthenticatedAt.Equal(want.AuthenticatedAt) {
		t.Errorf("AuthenticatedAt: got %v, want %v", got.AuthenticatedAt, want.AuthenticatedAt)
	}
	if !got.CreatedAt.Equal(want.CreatedAt) {
		t.Errorf("CreatedAt: got %v, want %v", got.CreatedAt, want.CreatedAt)
	}
	if !got.ExpiresAt.Equal(want.ExpiresAt) {
		t.Errorf("ExpiresAt: got %v, want %v", got.ExpiresAt, want.ExpiresAt)
	}
	if !ptrTimeEqual(got.RevokedAt, want.RevokedAt) {
		t.Errorf("RevokedAt: got %v, want %v", got.RevokedAt, want.RevokedAt)
	}
}

func TestRtToDocRtToEntityRoundtrip(t *testing.T) {
	revokedAt := time.Now().Round(0).Add(-time.Hour)

	t.Run("active token", func(t *testing.T) {
		rt := newTestRefreshToken("rt-1", "user-1", "hash-abc", 30*24*time.Hour)
		got, err := rtToEntity(rtToDoc(rt))
		if err != nil {
			t.Fatalf("rtToEntity: %v", err)
		}
		assertRefreshTokenEqual(t, rt, got)
	})

	t.Run("revoked token", func(t *testing.T) {
		rt := newTestRefreshToken("rt-2", "user-2", "hash-def", 30*24*time.Hour)
		rt.RevokedAt = &revokedAt
		got, err := rtToEntity(rtToDoc(rt))
		if err != nil {
			t.Fatalf("rtToEntity: %v", err)
		}
		assertRefreshTokenEqual(t, rt, got)
	})
}

func TestRtToEntityScopeError(t *testing.T) {
	tests := []struct {
		name  string
		scope string
	}{
		{"invalid scope value", "invalid_scope"},
		{"empty scope", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			doc := &refreshTokenDoc{Scope: tc.scope}
			_, err := rtToEntity(doc)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
		})
	}
}

func TestFileRefreshTokenRepository(t *testing.T) {
	ctx := context.Background()

	t.Run("Save and FindByTokenHash", func(t *testing.T) {
		repo, err := NewFileRefreshTokenRepository(newRTFileStore(t))
		if err != nil {
			t.Fatalf("NewFileRefreshTokenRepository: %v", err)
		}
		rt := newTestRefreshToken("rt-1", "user-1", "hash-abc", 30*24*time.Hour)
		if err := repo.Save(ctx, rt); err != nil {
			t.Fatalf("Save: %v", err)
		}
		found, err := repo.FindByTokenHash(ctx, rt.TokenHash)
		if err != nil {
			t.Fatalf("FindByTokenHash: %v", err)
		}
		if found.ID != rt.ID {
			t.Errorf("ID: got %q, want %q", found.ID, rt.ID)
		}
	})

	t.Run("FindByTokenHash not found", func(t *testing.T) {
		repo, err := NewFileRefreshTokenRepository(newRTFileStore(t))
		if err != nil {
			t.Fatalf("NewFileRefreshTokenRepository: %v", err)
		}
		_, err = repo.FindByTokenHash(ctx, "nonexistent-hash")
		if !errors.Is(err, coreerror.ErrNotFound) {
			t.Errorf("expected ErrNotFound, got %v", err)
		}
	})

	t.Run("RevokeByTokenHash revokes active token", func(t *testing.T) {
		repo, err := NewFileRefreshTokenRepository(newRTFileStore(t))
		if err != nil {
			t.Fatalf("NewFileRefreshTokenRepository: %v", err)
		}
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

	t.Run("RevokeByTokenHash already revoked returns ErrNotFound", func(t *testing.T) {
		repo, err := NewFileRefreshTokenRepository(newRTFileStore(t))
		if err != nil {
			t.Fatalf("NewFileRefreshTokenRepository: %v", err)
		}
		rt := newTestRefreshToken("rt-1", "user-1", "hash-revoked", 30*24*time.Hour)
		now := time.Now()
		rt.RevokedAt = &now
		if err := repo.Save(ctx, rt); err != nil {
			t.Fatalf("Save: %v", err)
		}
		if err := repo.RevokeByTokenHash(ctx, rt.TokenHash); !errors.Is(err, coreerror.ErrNotFound) {
			t.Errorf("expected ErrNotFound, got %v", err)
		}
	})

	t.Run("RevokeByTokenHash expired token returns ErrNotFound", func(t *testing.T) {
		repo, err := NewFileRefreshTokenRepository(newRTFileStore(t))
		if err != nil {
			t.Fatalf("NewFileRefreshTokenRepository: %v", err)
		}
		rt := newTestRefreshToken("rt-1", "user-1", "hash-expired", -time.Hour)
		if err := repo.Save(ctx, rt); err != nil {
			t.Fatalf("Save: %v", err)
		}
		if err := repo.RevokeByTokenHash(ctx, rt.TokenHash); !errors.Is(err, coreerror.ErrNotFound) {
			t.Errorf("expected ErrNotFound, got %v", err)
		}
	})

	t.Run("RevokeByTokenHash nonexistent returns ErrNotFound", func(t *testing.T) {
		repo, err := NewFileRefreshTokenRepository(newRTFileStore(t))
		if err != nil {
			t.Fatalf("NewFileRefreshTokenRepository: %v", err)
		}
		if err := repo.RevokeByTokenHash(ctx, "does-not-exist"); !errors.Is(err, coreerror.ErrNotFound) {
			t.Errorf("expected ErrNotFound, got %v", err)
		}
	})

	t.Run("RevokeAllForUser revokes only active tokens for target user", func(t *testing.T) {
		repo, err := NewFileRefreshTokenRepository(newRTFileStore(t))
		if err != nil {
			t.Fatalf("NewFileRefreshTokenRepository: %v", err)
		}

		userA := entity.UserID("user-a")
		userB := entity.UserID("user-b")

		rtA1 := newTestRefreshToken("rt-a1", string(userA), "hash-a1", 30*24*time.Hour)
		rtA2 := newTestRefreshToken("rt-a2", string(userA), "hash-a2", 30*24*time.Hour)
		rtARevoked := newTestRefreshToken("rt-a3", string(userA), "hash-a3", 30*24*time.Hour)
		revokedAt := time.Now()
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
