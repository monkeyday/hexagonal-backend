package usecase

import "context"

type Dispatcher interface {
	Dispatch(ctx context.Context, cmd any) (any, error)
}

type UseCase interface {
	Execute(ctx context.Context, cmd any) (any, error)
}
