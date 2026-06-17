package adapter

import (
	"fmt"
	"time"

	"sc/core/crypto"
	"sc/modules/auth/domain/entity"
)

// userDoc is the persistence representation of entity.User, shared by the file
// and Mongo user repositories. Email is stored encrypted with a blind index for
// equality lookups; the plaintext never touches storage.
type userDoc struct {
	ID                     string     `json:"id"                       bson:"_id"`
	TenantID               string     `json:"tenant_id"                bson:"tenant_id"`
	Username               string     `json:"username"                 bson:"username"`
	Nickname               string     `json:"nickname"                 bson:"nickname"`
	Password               string     `json:"password"                 bson:"password"`
	EmailCiphertext        string     `json:"email_ciphertext"         bson:"email_ciphertext"`
	EmailBlindIndex        string     `json:"email_blind_index"        bson:"email_blind_index"`
	EmailVerified          bool       `json:"email_verified"           bson:"email_verified"`
	PasswordResetTokenHash *string    `json:"password_reset_token_hash,omitempty" bson:"password_reset_token_hash,omitempty"`
	PasswordResetExpiresAt *time.Time `json:"password_reset_expires_at,omitempty" bson:"password_reset_expires_at,omitempty"`
	SessionsInvalidatedAt  *time.Time `json:"sessions_invalidated_at,omitempty"   bson:"sessions_invalidated_at,omitempty"`
	FailedLoginAttempts    int        `json:"failed_login_attempts"               bson:"failed_login_attempts"`
	LockedUntil            *time.Time `json:"locked_until,omitempty"              bson:"locked_until,omitempty"`
	CreatedAt              time.Time  `json:"created_at"               bson:"created_at"`
	UpdatedAt              time.Time  `json:"updated_at"               bson:"updated_at"`
}

type userCodec struct{ cipher *crypto.Cipher }

func newUserCodec(c *crypto.Cipher) *userCodec { return &userCodec{cipher: c} }

func (uc *userCodec) toDoc(u *entity.User) *userDoc {
	ciphertext, err := uc.cipher.Encrypt(u.Email)
	if err != nil {
		panic(fmt.Sprintf("encrypt email: %v", err))
	}
	return &userDoc{
		ID:                     string(u.ID),
		TenantID:               string(u.TenantID),
		Username:               u.Username,
		Nickname:               u.Nickname,
		Password:               u.Password,
		EmailCiphertext:        ciphertext,
		EmailBlindIndex:        uc.cipher.BlindIndex(u.Email),
		EmailVerified:          u.EmailVerified,
		PasswordResetTokenHash: u.PasswordResetTokenHash,
		PasswordResetExpiresAt: u.PasswordResetExpiresAt,
		SessionsInvalidatedAt:  u.SessionsInvalidatedAt,
		FailedLoginAttempts:    u.FailedLoginAttempts,
		LockedUntil:            u.LockedUntil,
		CreatedAt:              u.CreatedAt,
		UpdatedAt:              u.UpdatedAt,
	}
}

func (uc *userCodec) toEntity(d *userDoc) (*entity.User, error) {
	email, err := uc.cipher.Decrypt(d.EmailCiphertext)
	if err != nil {
		return nil, fmt.Errorf("decrypt email for user %s: %w", d.ID, err)
	}
	tenantID := entity.TenantID(d.TenantID)
	if tenantID == "" {
		tenantID = entity.DefaultTenantID
	}
	return &entity.User{
		ID:                     entity.UserID(d.ID),
		TenantID:               tenantID,
		Username:               d.Username,
		Nickname:               d.Nickname,
		Password:               d.Password,
		Email:                  email,
		EmailVerified:          d.EmailVerified,
		PasswordResetTokenHash: d.PasswordResetTokenHash,
		PasswordResetExpiresAt: d.PasswordResetExpiresAt,
		SessionsInvalidatedAt:  d.SessionsInvalidatedAt,
		FailedLoginAttempts:    d.FailedLoginAttempts,
		LockedUntil:            d.LockedUntil,
		CreatedAt:              d.CreatedAt,
		UpdatedAt:              d.UpdatedAt,
	}, nil
}
