package adapter

import (
	"context"

	"sc/core/crypto"
	coreerror "sc/core/error"
	filerepo "sc/infrastructure/repository/file"
	"sc/modules/auth/domain/entity"
	"sc/modules/auth/port"
)

var _ port.UserRepository = (*UserRepository)(nil)

type UserRepository struct {
	repo *filerepo.FileRepository[entity.User, userDoc]
}

func NewUserRepository(store *filerepo.FileStore, c *crypto.Cipher) (*UserRepository, error) {
	codec := newUserCodec(c)
	repo, err := filerepo.New[entity.User, userDoc](
		store, codec.toDoc, codec.toEntity, func(u *entity.User) string { return string(u.ID) },
	)
	if err != nil {
		return nil, err
	}
	return &UserRepository{repo: repo}, nil
}

func (r *UserRepository) CreateUser(_ context.Context, user *entity.User) error {
	return r.repo.CreateIfFieldNotExists("Email", user.Email, user)
}

func (r *UserRepository) FindByEmail(_ context.Context, tenantID entity.TenantID, email string) (*entity.User, error) {
	// The generic file store indexes a single field, so we match on email and
	// then guard the tenant. Email is a unique per tenant; in the single-realm
	// dev backend this is exact. The multi-tenant production path is Mongo.
	user, err := r.repo.FindByField("Email", email)
	if err != nil {
		return nil, err
	}
	if user.TenantID != tenantID {
		return nil, coreerror.ErrNotFound
	}
	return user, nil
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
