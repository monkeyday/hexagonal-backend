package adapter

import (
	"testing"
	"time"

	crypto "sc/core/crypto"
	filerepo "sc/infrastructure/repository/file"
	"sc/modules/auth/domain/entity"
	"sc/modules/auth/port"
)

var (
	testEncKey = []byte("12345678901234567890123456789012") // 32 bytes
	testBIKey  = []byte("blind-index-key-for-testing-only")
)

func testCipher(t *testing.T) *crypto.Cipher {
	t.Helper()
	c, err := crypto.NewCipher(testEncKey, testBIKey)
	if err != nil {
		t.Fatalf("crypto.NewCipher: %v", err)
	}
	return c
}

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
		TenantID:  entity.DefaultTenantID,
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
	if got.TenantID != want.TenantID {
		t.Errorf("TenantID: got %q, want %q", got.TenantID, want.TenantID)
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

	codec := newUserCodec(testCipher(t))

	t.Run("nil pointer fields", func(t *testing.T) {
		u := &entity.User{
			ID:            entity.UserID("user-1"),
			TenantID:      entity.DefaultTenantID,
			Username:      "testuser",
			Nickname:      "testnick",
			Password:      "hashed",
			Email:         "test@example.com",
			EmailVerified: true,
			CreatedAt:     now,
			UpdatedAt:     now,
		}
		got, err := codec.toEntity(codec.toDoc(u))
		if err != nil {
			t.Fatalf("toEntity: %v", err)
		}
		assertUserEqual(t, u, got)
	})

	t.Run("all pointer fields set", func(t *testing.T) {
		u := &entity.User{
			ID:                     entity.UserID("user-2"),
			TenantID:               entity.DefaultTenantID,
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
		got, err := codec.toEntity(codec.toDoc(u))
		if err != nil {
			t.Fatalf("toEntity: %v", err)
		}
		assertUserEqual(t, u, got)
	})

	t.Run("email and TenantID preserved", func(t *testing.T) {
		u := &entity.User{
			ID:        entity.UserID("user-3"),
			TenantID:  entity.TenantID("acme"),
			Email:     "preserved@example.com",
			Password:  "hashed3",
			CreatedAt: now,
			UpdatedAt: now,
		}
		doc := codec.toDoc(u)
		if doc.EmailCiphertext == "" {
			t.Error("EmailCiphertext must not be empty")
		}
		if doc.EmailCiphertext == u.Email {
			t.Error("EmailCiphertext must not equal plaintext email")
		}
		if doc.EmailBlindIndex == "" {
			t.Error("EmailBlindIndex must not be empty")
		}
		got, err := codec.toEntity(doc)
		if err != nil {
			t.Fatalf("toEntity: %v", err)
		}
		if got.Email != u.Email {
			t.Errorf("Email round-trip: got %q, want %q", got.Email, u.Email)
		}
		if got.TenantID != u.TenantID {
			t.Errorf("TenantID round-trip: got %q, want %q", got.TenantID, u.TenantID)
		}
	})

	t.Run("empty TenantID in doc defaults to DefaultTenantID", func(t *testing.T) {
		doc := &userDoc{
			ID:       "user-4",
			TenantID: "",
			EmailCiphertext: func() string {
				ct, _ := testCipher(t).Encrypt("default-tenant@example.com")
				return ct
			}(),
			CreatedAt: now,
			UpdatedAt: now,
		}
		got, err := codec.toEntity(doc)
		if err != nil {
			t.Fatalf("toEntity: %v", err)
		}
		if got.TenantID != entity.DefaultTenantID {
			t.Errorf("TenantID: got %q, want %q", got.TenantID, entity.DefaultTenantID)
		}
	})
}

func TestFileUserRepository(t *testing.T) {
	runUserRepositoryContract(t, func(t *testing.T) port.UserRepository {
		repo, err := NewUserRepository(newUserFileStore(t), testCipher(t))
		if err != nil {
			t.Fatalf("NewUserRepository: %v", err)
		}
		return repo
	})
}
