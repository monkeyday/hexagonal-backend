package entity

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"time"
	"unicode"

	"golang.org/x/crypto/bcrypt"
)

const PasswordResetTokenTTL = 15 * time.Minute

// TODO: rename User → Identity and narrow it to auth-only fields (ID, Email, PasswordHash,
// EmailVerified, PasswordResetTokenHash, PasswordResetExpiresAt) once a separate user module
// is introduced. Profile fields (Username, Nickname, CreatedAt, UpdatedAt) belong in the user
// module's User entity. The /userinfo endpoint should then fetch profile data from that module
// via a UserRepository port, using Identity.ID as the shared key.
type User struct {
	CreatedAt              time.Time
	UpdatedAt              time.Time
	ID                     UserID
	Username               string
	Nickname               string
	Password               string // bcrypt hash
	Email                  string
	EmailVerified          bool
	PasswordResetTokenHash *string    // SHA-256 hex of the raw reset token; nil means no active reset
	PasswordResetExpiresAt *time.Time // nil means no active reset
	SessionsInvalidatedAt  *time.Time // refresh tokens issued at or before this time are rejected
}

type UserArgs struct {
	Username      string
	Nickname      string
	Password      string
	Email         string
	EmailVerified bool
}

func NewUser(args UserArgs) (*User, error) {
	if err := validatePassword(args.Password); err != nil {
		return nil, err
	}
	return &User{
		ID:            NewUserID(),
		Username:      args.Username,
		Nickname:      args.Nickname,
		Password:      hashPassword(args.Password),
		Email:         args.Email,
		EmailVerified: args.EmailVerified,
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}, nil
}

func validatePassword(p string) error {
	if len(p) < 8 {
		return errors.New("password must be at least 8 characters")
	}
	var hasUpper, hasLower, hasDigit, hasSpecial bool
	for _, r := range p {
		switch {
		case unicode.IsUpper(r):
			hasUpper = true
		case unicode.IsLower(r):
			hasLower = true
		case unicode.IsDigit(r):
			hasDigit = true
		case unicode.IsPunct(r) || unicode.IsSymbol(r):
			hasSpecial = true
		}
	}
	if !hasUpper {
		return errors.New("password must contain at least one uppercase letter")
	}
	if !hasLower {
		return errors.New("password must contain at least one lowercase letter")
	}
	if !hasDigit {
		return errors.New("password must contain at least one digit")
	}
	if !hasSpecial {
		return errors.New("password must contain at least one special character")
	}
	return nil
}

func (u *User) ValidatePassword(password string) error {
	return bcrypt.CompareHashAndPassword([]byte(u.Password), []byte(password))
}

type UpdateProfileArgs struct {
	Username *string
	Nickname *string
	Email    *string
}

func (u *User) UpdateProfile(args UpdateProfileArgs) {
	if args.Username != nil {
		u.Username = *args.Username
	}
	if args.Nickname != nil {
		u.Nickname = *args.Nickname
	}
	if args.Email != nil {
		u.SetEmail(*args.Email)
	}
	u.UpdatedAt = time.Now()
}

func (u *User) SetEmail(v string) {
	if u.Email == v {
		return
	}
	u.Email = v
	u.EmailVerified = false
}

func (u *User) SetPasswordResetToken(rawToken string, ttl time.Duration) {
	u.PasswordResetTokenHash = new(Hash(rawToken))
	u.PasswordResetExpiresAt = new(time.Now().Add(ttl))
	u.UpdatedAt = time.Now()
}

func (u *User) IsResetTokenExpired() bool {
	return u.PasswordResetExpiresAt == nil || time.Now().After(*u.PasswordResetExpiresAt)
}

func (u *User) ValidateResetToken(rawToken string) bool {
	return u.PasswordResetTokenHash != nil && *u.PasswordResetTokenHash == Hash(rawToken) && !u.IsResetTokenExpired()
}

func (u *User) InvalidateSessions() {
	now := time.Now()
	u.SessionsInvalidatedAt = &now
	u.UpdatedAt = now
}

func (u *User) ClearPasswordResetToken() {
	u.PasswordResetTokenHash = nil
	u.PasswordResetExpiresAt = nil
	u.UpdatedAt = time.Now()
}

func (u *User) SetPassword(str string) error {
	if err := validatePassword(str); err != nil {
		return err
	}
	u.Password = hashPassword(str)
	u.UpdatedAt = time.Now()
	return nil
}

func GeneratePasswordResetToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func hashPassword(password string) string {
	hashed, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		panic(err)
	}
	return string(hashed)
}
