package port

import (
	"context"
	"sc/modules/auth/domain/entity"
)

type RefreshTokenRepository interface {
	Save(ctx context.Context, rt *entity.RefreshToken) error
	FindByTokenHash(ctx context.Context, tokenHash string) (*entity.RefreshToken, error)
	RevokeByTokenHash(ctx context.Context, tokenHash string) error
	RevokeAllForUser(ctx context.Context, userID entity.UserID) error
}
