package adapter

// Note: MongoRefreshTokenRepository creates a TTL index on expires_at at startup.

import (
	"context"
	"strings"

	coreerror "sc/core/error"
	filerepo "sc/infrastructure/repository/file"
	"sc/modules/auth/domain/entity"
	"sc/modules/auth/port"
	"time"
)

var _ port.RefreshTokenRepository = (*FileRefreshTokenRepository)(nil)

type refreshTokenDoc struct {
	ID              string     `json:"id"               bson:"_id"`
	UserID          string     `json:"user_id"          bson:"user_id"`
	TokenHash       string     `json:"token_hash"       bson:"token_hash"`
	Scope           string     `json:"scope"            bson:"scope"` // stored as a space-separated string
	DeviceID        string     `json:"device_id"        bson:"device_id"`
	AuthenticatedAt time.Time  `json:"authenticated_at" bson:"authenticated_at"`
	CreatedAt       time.Time  `json:"created_at"       bson:"created_at"`
	ExpiresAt       time.Time  `json:"expires_at"       bson:"expires_at"`
	RevokedAt       *time.Time `json:"revoked_at"       bson:"revoked_at"`
}

func rtToDoc(rt *entity.RefreshToken) *refreshTokenDoc {
	return &refreshTokenDoc{
		ID:              rt.ID,
		UserID:          string(rt.UserID),
		TokenHash:       rt.TokenHash,
		Scope:           rt.Scope.String(),
		DeviceID:        rt.DeviceID,
		AuthenticatedAt: rt.AuthenticatedAt,
		CreatedAt:       rt.CreatedAt,
		ExpiresAt:       rt.ExpiresAt,
		RevokedAt:       rt.RevokedAt,
	}
}

func rtToEntity(d *refreshTokenDoc) (*entity.RefreshToken, error) {
	scope, err := entity.NewScope(strings.Fields(d.Scope))
	if err != nil {
		return nil, err
	}
	return &entity.RefreshToken{
		ID:              d.ID,
		UserID:          entity.UserID(d.UserID),
		TokenHash:       d.TokenHash,
		Scope:           scope,
		DeviceID:        d.DeviceID,
		AuthenticatedAt: d.AuthenticatedAt,
		CreatedAt:       d.CreatedAt,
		ExpiresAt:       d.ExpiresAt,
		RevokedAt:       d.RevokedAt,
	}, nil
}

type FileRefreshTokenRepository struct {
	repo *filerepo.FileRepository[entity.RefreshToken, refreshTokenDoc]
}

func NewFileRefreshTokenRepository(store *filerepo.FileStore) (*FileRefreshTokenRepository, error) {
	repo, err := filerepo.New[entity.RefreshToken, refreshTokenDoc](
		store, nil,
		rtToDoc, rtToEntity,
		func(rt *entity.RefreshToken) string { return rt.ID },
	)
	if err != nil {
		return nil, err
	}
	return &FileRefreshTokenRepository{repo: repo}, nil
}

func (r *FileRefreshTokenRepository) Save(_ context.Context, rt *entity.RefreshToken) error {
	return r.repo.Save(rt)
}

func (r *FileRefreshTokenRepository) FindByTokenHash(_ context.Context, tokenHash string) (*entity.RefreshToken, error) {
	return r.repo.FindByField("TokenHash", tokenHash)
}

func (r *FileRefreshTokenRepository) RevokeByTokenHash(_ context.Context, tokenHash string) error {
	return r.repo.UpdateByField("TokenHash", tokenHash, func(rt *entity.RefreshToken) error {
		if rt.RevokedAt != nil || rt.ExpiresAt.Before(time.Now()) {
			return coreerror.ErrNotFound
		}
		rt.RevokedAt = new(time.Now())
		return nil
	})
}

func (r *FileRefreshTokenRepository) RevokeAllForUser(_ context.Context, userID entity.UserID) error {
	for _, rt := range r.repo.All() {
		if rt.UserID == userID && rt.RevokedAt == nil {
			cp := *rt
			cp.RevokedAt = new(time.Now())
			if err := r.repo.Save(&cp); err != nil {
				return err
			}
		}
	}
	return nil
}
