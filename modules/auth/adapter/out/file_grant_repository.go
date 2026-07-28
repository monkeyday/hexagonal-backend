package adapter

// Note: MongoGrantRepository creates a TTL index on expires_at at startup.

import (
	"context"
	"time"

	coreerror "sc/core/error"
	filerepo "sc/infrastructure/repository/file"
	"sc/modules/auth/domain/entity"
	"sc/modules/auth/port"
)

var _ port.GrantRepository = (*FileGrantRepository)(nil)

type FileGrantRepository struct {
	repo *filerepo.FileRepository[entity.Grant, grantDoc]
}

func NewFileGrantRepository(store *filerepo.FileStore) (*FileGrantRepository, error) {
	repo, err := filerepo.New[entity.Grant, grantDoc](
		store,
		grantToDoc, grantToEntity,
		func(g *entity.Grant) string { return string(g.ID) },
	)
	if err != nil {
		return nil, err
	}
	return &FileGrantRepository{repo: repo}, nil
}

func (r *FileGrantRepository) Save(_ context.Context, g *entity.Grant) error {
	return r.repo.Save(g)
}

func (r *FileGrantRepository) FindByID(_ context.Context, grantID entity.GrantID) (*entity.Grant, error) {
	return r.repo.FindByField("ID", string(grantID))
}

func (r *FileGrantRepository) Revoke(_ context.Context, grantID entity.GrantID, at time.Time) error {
	return r.repo.UpdateByField("ID", string(grantID), func(g *entity.Grant) error {
		if g.RevokedAt != nil {
			return coreerror.ErrNotFound
		}
		g.RevokedAt = &at
		return nil
	})
}
