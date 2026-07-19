package port

import (
	"context"
	"sc/modules/auth/domain/entity"
)

type UserRepository interface {
	CreateUser(ctx context.Context, user *entity.User) error
	FindByEmail(ctx context.Context, tenantID entity.TenantID, email string) (*entity.User, error)
	FindByID(ctx context.Context, id entity.UserID) (*entity.User, error)
	FindByPasswordResetTokenHash(ctx context.Context, tokenHash string) (*entity.User, error)
	Save(ctx context.Context, user *entity.User) error
	UpdateByPasswordResetTokenHash(ctx context.Context, tokenHash string, update func(*entity.User) error) error
}
