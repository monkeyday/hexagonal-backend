package binding

import (
	"errors"
	"fmt"
	"io"
	"net/url"
	"reflect"
	"time"

	"github.com/gin-gonic/gin"
	ginbinding "github.com/gin-gonic/gin/binding"
)

func init() {
	// Validation is handled by core/usecase after binding; disable Gin's built-in validator.
	ginbinding.Validator = nil
}

// leafTypes are struct types whose fields must not be traversed for binding tags.
// These are stdlib value types with no meaningful binding tags in their internals.
var leafTypes = map[reflect.Type]struct{}{
	reflect.TypeOf(time.Time{}): {},
}

func Bind(ginCtx *gin.Context, obj any) error {
	v := reflect.ValueOf(obj)
	if v.Kind() != reflect.Ptr || v.IsNil() {
		return fmt.Errorf("binding.Bind: obj must be a non-nil pointer, got %T", obj)
	}

	if err := ginCtx.ShouldBindUri(obj); err != nil {
		return err
	}
	if err := ginCtx.ShouldBindQuery(obj); err != nil {
		return err
	}
	if err := ginCtx.ShouldBindHeader(obj); err != nil {
		return err
	}

	// An empty body (io.EOF) is not an error.
	if err := ginCtx.ShouldBind(obj); err != nil && !errors.Is(err, io.EOF) {
		return err
	}

	return bindFromContext(ginCtx, obj)
}

func bindFromContext(ginCtx *gin.Context, obj any) error {
	v := reflect.ValueOf(obj)
	if v.Kind() != reflect.Ptr || v.IsNil() {
		return fmt.Errorf("binding.Bind: obj must be a non-nil pointer, got %T", obj)
	}
	traverseFields(v, func(fv reflect.Value, field reflect.StructField) bool {
		switch {
		case hasTag(field, "ctx"):
			if val, ok := ginCtx.Get(field.Tag.Get("ctx")); ok {
				setField(fv, val)
			}
			return true
		case hasTag(field, "file"):
			if fh, err := ginCtx.FormFile(field.Tag.Get("file")); err == nil {
				setField(fv, fh)
			}
			return true
		case hasTag(field, "cookie"):
			if val, err := ginCtx.Cookie(field.Tag.Get("cookie")); err == nil {
				setField(fv, val)
			}
			return true
		case hasTag(field, "normalize"):
			if fv.Kind() == reflect.String && field.Tag.Get("normalize") == "uri" {
				if raw := fv.String(); raw != "" {
					fv.SetString(normalizeURI(raw))
				}
			}
			return true
		}
		return false
	})
	return nil
}

func traverseFields(v reflect.Value, fn func(reflect.Value, reflect.StructField) bool) {
	switch v.Kind() {
	case reflect.Ptr:
		if !v.IsNil() {
			traverseFields(v.Elem(), fn)
		}
	case reflect.Struct:
		if _, skip := leafTypes[v.Type()]; skip {
			return
		}
		t := v.Type()
		for i := range t.NumField() {
			fv := v.Field(i)
			if !fv.CanSet() {
				continue
			}
			if !fn(fv, t.Field(i)) {
				traverseFields(fv, fn)
			}
		}
	case reflect.Slice:
		for i := range v.Len() {
			traverseFields(v.Index(i), fn)
		}
	case reflect.Map:
		for _, key := range v.MapKeys() {
			elem := v.MapIndex(key)
			// MapIndex returns a non-addressable copy; must allocate, mutate, then write back.
			ptr := reflect.New(elem.Type())
			ptr.Elem().Set(elem)
			traverseFields(ptr, fn)
			v.SetMapIndex(key, ptr.Elem())
		}
	}
}

func hasTag(field reflect.StructField, tag string) bool {
	v := field.Tag.Get(tag)
	return v != "" && v != "-"
}

func setField(fv reflect.Value, val any) {
	rv := reflect.ValueOf(val)
	if !rv.IsValid() {
		return
	}
	switch {
	case rv.Type().AssignableTo(fv.Type()):
		fv.Set(rv)
	case rv.Type().ConvertibleTo(fv.Type()):
		fv.Set(rv.Convert(fv.Type()))
	}
}

// normalizeURI returns the canonical form of a URI (e.g. lowercased scheme).
// Fragments are preserved so the redirect_uri validator can reject them explicitly.
func normalizeURI(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	return u.String()
}
