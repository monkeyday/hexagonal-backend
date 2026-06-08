package uow

import "context"

type UnitOfWork interface {
	Do(ctx context.Context, fn func(ctx context.Context) (any, error)) (any, error)
}

// NoopUnitOfWork satisfies UnitOfWork without any transactional guarantees.
// Use it for storage backends that do not support transactions (e.g. file store).
type NoopUnitOfWork struct{}

func (n *NoopUnitOfWork) Do(ctx context.Context, fn func(context.Context) (any, error)) (any, error) {
	return fn(ctx)
}
