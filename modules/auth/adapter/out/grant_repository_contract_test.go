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

// runGrantContract exercises the behaviour every GrantRepository implementation
// must share. newRepo returns a fresh, empty repository for each subtest so the
// drivers (file, mongo) stay isolated. This is the parity harness: file and
// mongo run the identical assertions.
func runGrantContract(t *testing.T, newRepo func(t *testing.T) port.GrantRepository) {
	ctx := context.Background()

	t.Run("Save then FindByID round-trips the grant", func(t *testing.T) {
		repo := newRepo(t)
		g := newTestGrant("user-1", "client-1")
		if err := repo.Save(ctx, g); err != nil {
			t.Fatalf("Save: %v", err)
		}
		found, err := repo.FindByID(ctx, g.ID)
		if err != nil {
			t.Fatalf("FindByID: %v", err)
		}
		assertGrantEqual(t, g, found)
	})

	t.Run("Save is an upsert on ID", func(t *testing.T) {
		repo := newRepo(t)
		g := newTestGrant("user-1", "client-1")
		if err := repo.Save(ctx, g); err != nil {
			t.Fatalf("Save: %v", err)
		}
		revokedAt := time.Now().UTC().Truncate(time.Millisecond)
		g.RevokedAt = &revokedAt
		if err := repo.Save(ctx, g); err != nil {
			t.Fatalf("Save (update): %v", err)
		}
		found, err := repo.FindByID(ctx, g.ID)
		if err != nil {
			t.Fatalf("FindByID: %v", err)
		}
		if found.RevokedAt == nil {
			t.Error("expected RevokedAt to persist after re-Save")
		}
	})

	t.Run("FindByID not found returns ErrNotFound", func(t *testing.T) {
		repo := newRepo(t)
		_, err := repo.FindByID(ctx, entity.NewGrantID())
		if !errors.Is(err, coreerror.ErrNotFound) {
			t.Errorf("expected ErrNotFound, got %v", err)
		}
	})

	t.Run("Revoke marks the grant revoked", func(t *testing.T) {
		repo := newRepo(t)
		g := newTestGrant("user-1", "client-1")
		if err := repo.Save(ctx, g); err != nil {
			t.Fatalf("Save: %v", err)
		}
		if err := repo.Revoke(ctx, g.ID, time.Now()); err != nil {
			t.Fatalf("Revoke: %v", err)
		}
		found, err := repo.FindByID(ctx, g.ID)
		if err != nil {
			t.Fatalf("FindByID: %v", err)
		}
		if found.RevokedAt == nil {
			t.Error("RevokedAt should be set after Revoke")
		}
		if found.IsValid() {
			t.Error("revoked grant should not be valid")
		}
	})

	t.Run("Revoke on already-revoked returns ErrNotFound", func(t *testing.T) {
		repo := newRepo(t)
		g := newTestGrant("user-1", "client-1")
		now := time.Now().UTC().Truncate(time.Millisecond)
		g.RevokedAt = &now
		if err := repo.Save(ctx, g); err != nil {
			t.Fatalf("Save: %v", err)
		}
		if err := repo.Revoke(ctx, g.ID, time.Now()); !errors.Is(err, coreerror.ErrNotFound) {
			t.Errorf("expected ErrNotFound, got %v", err)
		}
	})

	t.Run("Revoke on nonexistent returns ErrNotFound", func(t *testing.T) {
		repo := newRepo(t)
		if err := repo.Revoke(ctx, entity.NewGrantID(), time.Now()); !errors.Is(err, coreerror.ErrNotFound) {
			t.Errorf("expected ErrNotFound, got %v", err)
		}
	})
}

func newTestGrant(userID, clientID string) *entity.Grant {
	now := time.Now().UTC().Truncate(time.Millisecond)
	g := entity.NewGrant(entity.UserID(userID), entity.ClientID(clientID))
	g.CreatedAt = now
	g.AuthenticatedAt = now
	g.ExpiresAt = now.Add(entity.RefreshTokenTTL)
	return g
}

func assertGrantEqual(t *testing.T, want, got *entity.Grant) {
	t.Helper()
	if got.ID != want.ID {
		t.Errorf("ID: got %q, want %q", got.ID, want.ID)
	}
	if got.UserID != want.UserID {
		t.Errorf("UserID: got %q, want %q", got.UserID, want.UserID)
	}
	if got.ClientID != want.ClientID {
		t.Errorf("ClientID: got %q, want %q", got.ClientID, want.ClientID)
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
