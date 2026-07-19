package entity

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
)

const (
	ScopeOpenID  = "openid"
	ScopeEmail   = "email"
	ScopeProfile = "profile"
	ScopePhone   = "phone"
)

var SupportedScopes = []string{ScopeOpenID, ScopeEmail, ScopeProfile, ScopePhone}

type Scope struct {
	values []string
}

func NewScope(values []string) (Scope, error) {
	if len(values) == 0 {
		return Scope{}, fmt.Errorf("scope must not be empty")
	}
	for _, s := range values {
		if !slices.Contains(SupportedScopes, s) {
			return Scope{}, fmt.Errorf("unsupported scope: %s", s)
		}
	}
	return Scope{values: values}, nil
}

// MustParseScope parses a space-separated scope string and panics if invalid. For use in tests and init code.
func MustParseScope(raw string) Scope {
	s, err := NewScope(strings.Fields(raw))
	if err != nil {
		panic(err)
	}
	return s
}

func (s *Scope) String() string {
	return strings.Join(s.values, " ")
}

// Values return a copy of the scope values as a slice.
func (s *Scope) Values() []string {
	return slices.Clone(s.values)
}

func (s *Scope) Contains(scope string) bool {
	return slices.Contains(s.values, scope)
}

func (s *Scope) IsEmpty() bool {
	return len(s.values) == 0
}

func (s *Scope) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.String())
}

func (s *Scope) UnmarshalJSON(data []byte) error {
	var raw string
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	scope, err := NewScope(strings.Fields(raw))
	if err != nil {
		return err
	}
	*s = scope
	return nil
}
