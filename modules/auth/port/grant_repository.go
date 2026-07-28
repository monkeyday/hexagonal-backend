package port

import (
	"context"
	"time"

	"sc/modules/auth/domain/entity"
)

// GrantRepository persists and retrieves authentication grants.
//
// Contract:
//   - Save is an upsert on ID (same as RefreshTokenRepository.Save).
//   - FindByID returns coreerror.ErrNotFound when absent.
//   - Revoke only affects a grant whose RevokedAt is nil; when nothing matched
//     (absent or already revoked) it returns coreerror.ErrNotFound, mirroring
//     RevokeByTokenHash in mongo_refresh_token_repository.go:81-97.
type GrantRepository interface {
	Save(ctx context.Context, g *entity.Grant) error
	FindByID(ctx context.Context, grantID entity.GrantID) (*entity.Grant, error)
	Revoke(ctx context.Context, grantID entity.GrantID, at time.Time) error
}
