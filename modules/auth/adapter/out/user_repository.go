package adapter

import (
	"context"
	filerepo "sc/infrastructure/repository/file"
	"sc/modules/auth/domain/entity"
	"sc/modules/auth/port"
	"time"
)

var _ port.UserRepository = (*UserRepository)(nil)

type UserRepository struct {
	repo *filerepo.FileRepository[entity.User, userDoc]
}

func NewUserRepository(store *filerepo.FileStore, seed map[string]*entity.User) (*UserRepository, error) {
	repo, err := filerepo.New[entity.User, userDoc](
		store, seed,
		toDoc, toEntity,
		func(u *entity.User) string { return string(u.ID) },
	)
	if err != nil {
		return nil, err
	}
	return &UserRepository{repo: repo}, nil
}

func (r *UserRepository) CreateUser(_ context.Context, user *entity.User) error {
	return r.repo.CreateIfFieldNotExists("Email", user.Email, user)
}

func (r *UserRepository) FindByEmail(_ context.Context, email string) (*entity.User, error) {
	return r.repo.FindByField("Email", email)
}

func (r *UserRepository) FindByID(_ context.Context, id entity.UserID) (*entity.User, error) {
	return r.repo.FindByField("ID", string(id))
}

func (r *UserRepository) FindByPasswordResetTokenHash(_ context.Context, tokenHash string) (*entity.User, error) {
	return r.repo.FindByField("PasswordResetTokenHash", tokenHash)
}

func (r *UserRepository) Save(_ context.Context, user *entity.User) error {
	return r.repo.Save(user)
}

func (r *UserRepository) UpdateByPasswordResetTokenHash(_ context.Context, tokenHash string, update func(*entity.User) error) error {
	return r.repo.UpdateByField("PasswordResetTokenHash", tokenHash, update)
}

type userDoc struct {
	ID                     string     `json:"id"                       bson:"_id"`
	Username               string     `json:"username"                 bson:"username"`
	Nickname               string     `json:"nickname"                 bson:"nickname"`
	Password               string     `json:"password"                 bson:"password"`
	Email                  string     `json:"email"                    bson:"email"`
	EmailVerified          bool       `json:"email_verified"           bson:"email_verified"`
	PasswordResetTokenHash *string    `json:"password_reset_token_hash,omitempty" bson:"password_reset_token_hash,omitempty"`
	PasswordResetExpiresAt *time.Time `json:"password_reset_expires_at,omitempty" bson:"password_reset_expires_at,omitempty"`
	SessionsInvalidatedAt  *time.Time `json:"sessions_invalidated_at,omitempty"   bson:"sessions_invalidated_at,omitempty"`
	CreatedAt              time.Time  `json:"created_at"               bson:"created_at"`
	UpdatedAt              time.Time  `json:"updated_at"               bson:"updated_at"`
}

func toDoc(u *entity.User) *userDoc {
	return &userDoc{
		ID:                     string(u.ID),
		Username:               u.Username,
		Nickname:               u.Nickname,
		Password:               u.Password,
		Email:                  u.Email,
		EmailVerified:          u.EmailVerified,
		PasswordResetTokenHash: u.PasswordResetTokenHash,
		PasswordResetExpiresAt: u.PasswordResetExpiresAt,
		SessionsInvalidatedAt:  u.SessionsInvalidatedAt,
		CreatedAt:              u.CreatedAt,
		UpdatedAt:              u.UpdatedAt,
	}
}

func toEntity(d *userDoc) (*entity.User, error) {
	return &entity.User{
		ID:                     entity.UserID(d.ID),
		Username:               d.Username,
		Nickname:               d.Nickname,
		Password:               d.Password,
		Email:                  d.Email,
		EmailVerified:          d.EmailVerified,
		PasswordResetTokenHash: d.PasswordResetTokenHash,
		PasswordResetExpiresAt: d.PasswordResetExpiresAt,
		SessionsInvalidatedAt:  d.SessionsInvalidatedAt,
		CreatedAt:              d.CreatedAt,
		UpdatedAt:              d.UpdatedAt,
	}, nil
}
