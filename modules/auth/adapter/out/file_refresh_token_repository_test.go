package adapter

import (
	"testing"
	"time"

	filerepo "sc/infrastructure/repository/file"
	"sc/modules/auth/domain/entity"
	"sc/modules/auth/port"
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
	// Millisecond precision so the value survives both JSON (file) and BSON
	// (mongo) round-trips identically — BSON datetimes are millisecond-grained.
	now := time.Now().UTC().Truncate(time.Millisecond)
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
	runRefreshTokenContract(t, func(t *testing.T) port.RefreshTokenRepository {
		repo, err := NewFileRefreshTokenRepository(newRTFileStore(t))
		if err != nil {
			t.Fatalf("NewFileRefreshTokenRepository: %v", err)
		}
		return repo
	})
}
