package mongorepo

import (
	"context"
	"sc/core/uow"

	"go.mongodb.org/mongo-driver/mongo"
)

var _ uow.UnitOfWork = (*UnitOfWork)(nil)

type UnitOfWork struct {
	client *MongoClient
}

func NewUnitOfWork(c *MongoClient) *UnitOfWork {
	return &UnitOfWork{client: c}
}

func (u *UnitOfWork) Do(ctx context.Context, fn func(ctx context.Context) (any, error)) (any, error) {
	return u.client.WithTransaction(ctx, func(sessCtx mongo.SessionContext) (any, error) {
		return fn(sessCtx)
	})
}
