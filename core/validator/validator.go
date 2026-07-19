package validator

import (
	"errors"
	"net/url"
	"regexp"
	"strings"
	"sync"

	"github.com/go-playground/validator/v10"
)

const (
	tagPassword     = "passwordPattern"
	passwordPattern = `^(?i)[A-Za-z0-9!@#$%]{8,64}$`
	tagHasWord      = "has_word"
	tagHasAnyWord   = "has_any_word"
	tagRedirectURI  = "redirect_uri"
)

var (
	v             *validator.Validate
	initErr       error
	once          sync.Once
	passwordRegex = regexp.MustCompile(passwordPattern)
)

func initValidator() {
	once.Do(func() {
		v = validator.New()
		errs := []error{
			v.RegisterValidation(tagPassword, passwordValidation),
			v.RegisterValidation(tagHasWord, hasWordValidation),
			v.RegisterValidation(tagHasAnyWord, hasAnyWordValidation),
			v.RegisterValidation(tagRedirectURI, redirectURIValidation),
		}
		initErr = errors.Join(errs...)
	})
}

func ValidateStruct(s any) error {
	initValidator()
	if initErr != nil {
		return errors.Join(errors.New("validator initialization failed"), initErr)
	}

	return v.Struct(s)
}

func passwordValidation(fl validator.FieldLevel) bool {
	return passwordRegex.MatchString(fl.Field().String())
}

func hasWordValidation(fl validator.FieldLevel) bool {
	actual := make(map[string]struct{})
	for _, s := range strings.Fields(fl.Field().String()) {
		actual[s] = struct{}{}
	}
	for _, w := range strings.Fields(fl.Param()) {
		if _, ok := actual[w]; !ok {
			return false
		}
	}
	return true
}

func redirectURIValidation(fl validator.FieldLevel) bool {
	raw := fl.Field().String()
	u, err := url.Parse(raw)
	if err != nil || !u.IsAbs() || u.Host == "" {
		return false
	}
	return u.Fragment == ""
}

func hasAnyWordValidation(fl validator.FieldLevel) bool {
	actual := make(map[string]struct{})
	for _, s := range strings.Fields(fl.Field().String()) {
		actual[s] = struct{}{}
	}
	for _, w := range strings.Fields(fl.Param()) {
		if _, ok := actual[w]; !ok {
			continue
		}
		return true
	}
	return false
}
