package adapter

import (
	"context"
	"errors"
	"testing"

	coreerror "sc/core/error"
	"sc/modules/auth/domain/entity"
	"sc/modules/auth/port"
)

// runUserRepositoryContract exercises the behaviour every UserRepository
// implementation must share. newRepo returns a fresh, empty repository per
// subtest. Everything here uses DefaultTenantID: cross-tenant email isolation
// is intentionally Mongo-only (the file backend is single-realm dev), so it is
// asserted separately, not in this shared contract.
func runUserRepositoryContract(t *testing.T, newRepo func(t *testing.T) port.UserRepository) {
	ctx := context.Background()

	t.Run("CreateUser then FindByEmail", func(t *testing.T) {
		repo := newRepo(t)
		u := newUserForTest("u1", "a@example.com")
		if err := repo.CreateUser(ctx, u); err != nil {
			t.Fatalf("CreateUser: %v", err)
		}
		found, err := repo.FindByEmail(ctx, entity.DefaultTenantID, u.Email)
		if err != nil {
			t.Fatalf("FindByEmail: %v", err)
		}
		if found.ID != u.ID {
			t.Errorf("ID: got %q, want %q", found.ID, u.ID)
		}
		if found.Email != u.Email {
			t.Errorf("Email: got %q, want %q", found.Email, u.Email)
		}
	})

	t.Run("CreateUser duplicate email returns ErrConflict", func(t *testing.T) {
		repo := newRepo(t)
		u1 := newUserForTest("u1", "dup@example.com")
		u2 := newUserForTest("u2", "dup@example.com")
		if err := repo.CreateUser(ctx, u1); err != nil {
			t.Fatalf("CreateUser u1: %v", err)
		}
		if err := repo.CreateUser(ctx, u2); !errors.Is(err, coreerror.ErrConflict) {
			t.Errorf("expected ErrConflict, got %v", err)
		}
	})

	t.Run("FindByEmail not found returns ErrNotFound", func(t *testing.T) {
		repo := newRepo(t)
		_, err := repo.FindByEmail(ctx, entity.DefaultTenantID, "missing@example.com")
		if !errors.Is(err, coreerror.ErrNotFound) {
			t.Errorf("expected ErrNotFound, got %v", err)
		}
	})

	t.Run("FindByID found and not found", func(t *testing.T) {
		repo := newRepo(t)
		u := newUserForTest("id-user-1", "b@example.com")
		if err := repo.CreateUser(ctx, u); err != nil {
			t.Fatalf("CreateUser: %v", err)
		}
		found, err := repo.FindByID(ctx, u.ID)
		if err != nil {
			t.Fatalf("FindByID: %v", err)
		}
		if found.Email != u.Email {
			t.Errorf("Email: got %q, want %q", found.Email, u.Email)
		}
		if _, err := repo.FindByID(ctx, "nonexistent-id"); !errors.Is(err, coreerror.ErrNotFound) {
			t.Errorf("expected ErrNotFound, got %v", err)
		}
	})

	t.Run("Save updates existing user", func(t *testing.T) {
		repo := newRepo(t)
		u := newUserForTest("save-u1", "save@example.com")
		if err := repo.CreateUser(ctx, u); err != nil {
			t.Fatalf("CreateUser: %v", err)
		}
		u.Nickname = "updated-nick"
		if err := repo.Save(ctx, u); err != nil {
			t.Fatalf("Save: %v", err)
		}
		found, err := repo.FindByEmail(ctx, entity.DefaultTenantID, u.Email)
		if err != nil {
			t.Fatalf("FindByEmail after Save: %v", err)
		}
		if found.Nickname != "updated-nick" {
			t.Errorf("Nickname: got %q, want updated-nick", found.Nickname)
		}
	})

	t.Run("FindByPasswordResetTokenHash found and not found", func(t *testing.T) {
		repo := newRepo(t)
		u := newUserForTest("reset-u1", "reset@example.com")
		hash := "sha256-reset-hash"
		u.PasswordResetTokenHash = &hash
		if err := repo.CreateUser(ctx, u); err != nil {
			t.Fatalf("CreateUser: %v", err)
		}
		found, err := repo.FindByPasswordResetTokenHash(ctx, hash)
		if err != nil {
			t.Fatalf("FindByPasswordResetTokenHash: %v", err)
		}
		if found.ID != u.ID {
			t.Errorf("ID: got %q, want %q", found.ID, u.ID)
		}
		if _, err := repo.FindByPasswordResetTokenHash(ctx, "wrong-hash"); !errors.Is(err, coreerror.ErrNotFound) {
			t.Errorf("expected ErrNotFound, got %v", err)
		}
	})

	t.Run("UpdateByPasswordResetTokenHash applies the mutation", func(t *testing.T) {
		repo := newRepo(t)
		u := newUserForTest("upd-u1", "upd@example.com")
		hash := "reset-hash-abc"
		u.PasswordResetTokenHash = &hash
		if err := repo.CreateUser(ctx, u); err != nil {
			t.Fatalf("CreateUser: %v", err)
		}
		if err := repo.UpdateByPasswordResetTokenHash(ctx, hash, func(u *entity.User) error {
			u.Nickname = "changed"
			return nil
		}); err != nil {
			t.Fatalf("UpdateByPasswordResetTokenHash: %v", err)
		}
		found, err := repo.FindByPasswordResetTokenHash(ctx, hash)
		if err != nil {
			t.Fatalf("FindByPasswordResetTokenHash after update: %v", err)
		}
		if found.Nickname != "changed" {
			t.Errorf("Nickname: got %q, want changed", found.Nickname)
		}
	})

	t.Run("UpdateByPasswordResetTokenHash not found returns ErrNotFound", func(t *testing.T) {
		repo := newRepo(t)
		err := repo.UpdateByPasswordResetTokenHash(ctx, "nonexistent-hash", func(*entity.User) error { return nil })
		if !errors.Is(err, coreerror.ErrNotFound) {
			t.Errorf("expected ErrNotFound, got %v", err)
		}
	})
}
