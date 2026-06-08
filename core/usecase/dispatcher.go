package usecase

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	coreerror "sc/core/error"

	"sc/core/validator"

	"github.com/rs/zerolog/log"
)

// validationErrCode matches autherrors.InvalidArguments so callers can use
// either constant when checking error returned from Dispatch().
const (
	validationErrCode   = 10001
	useCaseNotFoundCode = 10002
)

type Dispatcher interface {
	Dispatch(ctx context.Context, cmd any) (any, error)
}

type UseCase interface {
	Execute(ctx context.Context, cmd any) (any, error)
}

type Registry struct {
	useCases map[reflect.Type]UseCase
}

func NewRegistry() *Registry {
	return &Registry{
		useCases: make(map[reflect.Type]UseCase),
	}
}

func (r *Registry) Register(cmd any, uc UseCase) {
	if _, ok := r.useCases[reflect.TypeOf(cmd)]; ok {
		return
	}
	r.useCases[reflect.TypeOf(cmd)] = uc
}

func (r *Registry) Dispatch(ctx context.Context, cmd any) (result any, err error) {
	defer func() {
		if rec := recover(); rec != nil {
			log.Error().Interface("panic", rec)
			err = fmt.Errorf("panic in registry: %v", rec)
		}
	}()

	uc, err := r.find(cmd)
	if err != nil {
		return nil, err
	}

	if err := validator.ValidateStruct(cmd); err != nil {
		return nil, coreerror.NewErrorStruct(validationErrCode, http.StatusBadRequest, err)
	}

	return uc.Execute(ctx, cmd)
}

func (r *Registry) find(cmd any) (UseCase, error) {
	t := reflect.TypeOf(cmd)
	if t.Kind() == reflect.Ptr {
		t = t.Elem()
	}
	uc, ok := r.useCases[t]
	if !ok || uc == nil {
		return nil, coreerror.NewErrorStruct(useCaseNotFoundCode, http.StatusNotFound, errors.New("use case not found"))
	}
	return uc, nil
}
