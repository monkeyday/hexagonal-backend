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

func newUserFileStore(t *testing.T) *filerepo.FileStore {
	t.Helper()
	store, err := filerepo.NewFileStore(t.TempDir(), "users.json")
	if err != nil {
		t.Fatalf("NewFileStore: %v", err)
	}
	return store
}

func newUserForTest(id, email string) *entity.User {
	now := time.Now().Round(0)
	return &entity.User{
		ID:        entity.UserID(id),
		Username:  "user-" + id,
		Nickname:  "nick-" + id,
		Password:  "hashed-password",
		Email:     email,
		CreatedAt: now,
		UpdatedAt: now,
	}
}

func ptrTimeEqual(a, b *time.Time) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	return a.Equal(*b)
}

func ptrStringEqual(a, b *string) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	return *a == *b
}

func ptrStr(s *string) string {
	if s == nil {
		return "<nil>"
	}
	return *s
}

func assertUserEqual(t *testing.T, want, got *entity.User) {
	t.Helper()
	if got.ID != want.ID {
		t.Errorf("ID: got %q, want %q", got.ID, want.ID)
	}
	if got.Username != want.Username {
		t.Errorf("Username: got %q, want %q", got.Username, want.Username)
	}
	if got.Nickname != want.Nickname {
		t.Errorf("Nickname: got %q, want %q", got.Nickname, want.Nickname)
	}
	if got.Password != want.Password {
		t.Errorf("Password: got %q, want %q", got.Password, want.Password)
	}
	if got.Email != want.Email {
		t.Errorf("Email: got %q, want %q", got.Email, want.Email)
	}
	if got.EmailVerified != want.EmailVerified {
		t.Errorf("EmailVerified: got %v, want %v", got.EmailVerified, want.EmailVerified)
	}
	if !ptrStringEqual(got.PasswordResetTokenHash, want.PasswordResetTokenHash) {
		t.Errorf("PasswordResetTokenHash: got %s, want %s", ptrStr(got.PasswordResetTokenHash), ptrStr(want.PasswordResetTokenHash))
	}
	if !ptrTimeEqual(got.PasswordResetExpiresAt, want.PasswordResetExpiresAt) {
		t.Errorf("PasswordResetExpiresAt: got %v, want %v", got.PasswordResetExpiresAt, want.PasswordResetExpiresAt)
	}
	if !ptrTimeEqual(got.SessionsInvalidatedAt, want.SessionsInvalidatedAt) {
		t.Errorf("SessionsInvalidatedAt: got %v, want %v", got.SessionsInvalidatedAt, want.SessionsInvalidatedAt)
	}
	if !got.CreatedAt.Equal(want.CreatedAt) {
		t.Errorf("CreatedAt: got %v, want %v", got.CreatedAt, want.CreatedAt)
	}
	if !got.UpdatedAt.Equal(want.UpdatedAt) {
		t.Errorf("UpdatedAt: got %v, want %v", got.UpdatedAt, want.UpdatedAt)
	}
}

func TestToDocToEntityRoundtrip(t *testing.T) {
	now := time.Now().Round(0)
	hash := "abc123hash"
	expiry := now.Add(15 * time.Minute)
	invalidated := now.Add(-time.Hour)

	t.Run("nil pointer fields", func(t *testing.T) {
		u := &entity.User{
			ID:            entity.UserID("user-1"),
			Username:      "testuser",
			Nickname:      "testnick",
			Password:      "hashed",
			Email:         "test@example.com",
			EmailVerified: true,
			CreatedAt:     now,
			UpdatedAt:     now,
		}
		got, err := toEntity(toDoc(u))
		if err != nil {
			t.Fatalf("toEntity: %v", err)
		}
		assertUserEqual(t, u, got)
	})

	t.Run("all pointer fields set", func(t *testing.T) {
		u := &entity.User{
			ID:                     entity.UserID("user-2"),
			Username:               "testuser2",
			Nickname:               "testnick2",
			Password:               "hashed2",
			Email:                  "test2@example.com",
			EmailVerified:          false,
			PasswordResetTokenHash: &hash,
			PasswordResetExpiresAt: &expiry,
			SessionsInvalidatedAt:  &invalidated,
			CreatedAt:              now,
			UpdatedAt:              now,
		}
		got, err := toEntity(toDoc(u))
		if err != nil {
			t.Fatalf("toEntity: %v", err)
		}
		assertUserEqual(t, u, got)
	})
}

func TestFileUserRepository(t *testing.T) {
	ctx := context.Background()

	t.Run("CreateUser success and FindByEmail", func(t *testing.T) {
		repo, err := NewUserRepository(newUserFileStore(t), nil)
		if err != nil {
			t.Fatalf("NewUserRepository: %v", err)
		}
		u := newUserForTest("u1", "a@example.com")
		if err := repo.CreateUser(ctx, u); err != nil {
			t.Fatalf("CreateUser: %v", err)
		}
		found, err := repo.FindByEmail(ctx, u.Email)
		if err != nil {
			t.Fatalf("FindByEmail: %v", err)
		}
		if found.ID != u.ID {
			t.Errorf("ID: got %q, want %q", found.ID, u.ID)
		}
	})

	t.Run("CreateUser duplicate email returns ErrConflict", func(t *testing.T) {
		repo, err := NewUserRepository(newUserFileStore(t), nil)
		if err != nil {
			t.Fatalf("NewUserRepository: %v", err)
		}
		u1 := newUserForTest("u1", "dup@example.com")
		u2 := newUserForTest("u2", "dup@example.com")
		if err := repo.CreateUser(ctx, u1); err != nil {
			t.Fatalf("CreateUser u1: %v", err)
		}
		if err := repo.CreateUser(ctx, u2); !errors.Is(err, coreerror.ErrConflict) {
			t.Errorf("expected ErrConflict, got %v", err)
		}
	})

	t.Run("FindByEmail not found", func(t *testing.T) {
		repo, err := NewUserRepository(newUserFileStore(t), nil)
		if err != nil {
			t.Fatalf("NewUserRepository: %v", err)
		}
		_, err = repo.FindByEmail(ctx, "missing@example.com")
		if !errors.Is(err, coreerror.ErrNotFound) {
			t.Errorf("expected ErrNotFound, got %v", err)
		}
	})

	t.Run("FindByID found and not found", func(t *testing.T) {
		repo, err := NewUserRepository(newUserFileStore(t), nil)
		if err != nil {
			t.Fatalf("NewUserRepository: %v", err)
		}
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
		_, err = repo.FindByID(ctx, "nonexistent-id")
		if !errors.Is(err, coreerror.ErrNotFound) {
			t.Errorf("expected ErrNotFound, got %v", err)
		}
	})

	t.Run("Save updates existing user", func(t *testing.T) {
		repo, err := NewUserRepository(newUserFileStore(t), nil)
		if err != nil {
			t.Fatalf("NewUserRepository: %v", err)
		}
		u := newUserForTest("save-u1", "save@example.com")
		if err := repo.CreateUser(ctx, u); err != nil {
			t.Fatalf("CreateUser: %v", err)
		}
		u.Nickname = "updated-nick"
		if err := repo.Save(ctx, u); err != nil {
			t.Fatalf("Save: %v", err)
		}
		found, err := repo.FindByEmail(ctx, u.Email)
		if err != nil {
			t.Fatalf("FindByEmail after Save: %v", err)
		}
		if found.Nickname != "updated-nick" {
			t.Errorf("Nickname: got %q, want updated-nick", found.Nickname)
		}
	})

	t.Run("FindByPasswordResetTokenHash found and not found", func(t *testing.T) {
		repo, err := NewUserRepository(newUserFileStore(t), nil)
		if err != nil {
			t.Fatalf("NewUserRepository: %v", err)
		}
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
		_, err = repo.FindByPasswordResetTokenHash(ctx, "wrong-hash")
		if !errors.Is(err, coreerror.ErrNotFound) {
			t.Errorf("expected ErrNotFound, got %v", err)
		}
	})

	t.Run("UpdateByPasswordResetTokenHash success", func(t *testing.T) {
		repo, err := NewUserRepository(newUserFileStore(t), nil)
		if err != nil {
			t.Fatalf("NewUserRepository: %v", err)
		}
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

	t.Run("UpdateByPasswordResetTokenHash not found", func(t *testing.T) {
		repo, err := NewUserRepository(newUserFileStore(t), nil)
		if err != nil {
			t.Fatalf("NewUserRepository: %v", err)
		}
		err = repo.UpdateByPasswordResetTokenHash(ctx, "nonexistent-hash", func(*entity.User) error { return nil })
		if !errors.Is(err, coreerror.ErrNotFound) {
			t.Errorf("expected ErrNotFound, got %v", err)
		}
	})
}
