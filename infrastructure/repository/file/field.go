package filerepo

import (
	"fmt"
	"reflect"

	coreerror "sc/core/error"
	repo "sc/infrastructure/repository"
)

type Field string

func FindByField[T any](items map[string]*T, field Field, value string) (*T, error) {
	for _, item := range items {
		f := reflect.ValueOf(*item).FieldByName(string(field))
		if !f.IsValid() {
			return nil, repo.NewErrInvalidField(fmt.Errorf("unknown field %q on %T", field, *item))
		}
		switch f.Kind() {
		case reflect.String:
			if f.String() == value {
				return item, nil
			}
		case reflect.Ptr:
			if f.IsNil() {
				continue
			}
			if f.Elem().Kind() != reflect.String {
				return nil, repo.NewErrInvalidField(fmt.Errorf("field %q on %T is not a string pointer", field, *item))
			}
			if f.Elem().String() == value {
				return item, nil
			}
		default:
			return nil, repo.NewErrInvalidField(fmt.Errorf("field %q on %T is not a string", field, *item))
		}
	}
	return nil, coreerror.ErrNotFound
}
