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
		fieldValue, ok, err := stringFieldValue(item, field)
		if err != nil {
			return nil, err
		}
		if ok && fieldValue == value {
			return item, nil
		}
	}
	return nil, coreerror.ErrNotFound
}

func stringFieldValue[T any](item *T, field Field) (string, bool, error) {
	f := reflect.ValueOf(*item).FieldByName(string(field))
	if !f.IsValid() {
		return "", false, repo.NewErrInvalidField(fmt.Errorf("unknown field %q on %T", field, *item))
	}
	switch f.Kind() {
	case reflect.String:
		return f.String(), true, nil
	case reflect.Ptr:
		if f.IsNil() {
			return "", false, nil
		}
		if f.Elem().Kind() != reflect.String {
			return "", false, repo.NewErrInvalidField(fmt.Errorf("field %q on %T is not a string pointer", field, *item))
		}
		return f.Elem().String(), true, nil
	default:
		return "", false, repo.NewErrInvalidField(fmt.Errorf("field %q on %T is not a string", field, *item))
	}
}
