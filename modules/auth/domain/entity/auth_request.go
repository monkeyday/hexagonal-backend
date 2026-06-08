package entity

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net/url"
	"strings"
	"time"

	corevalidator "sc/core/validator"
)

const (
	AuthorizeRequestTTL     = 10 * time.Minute
	CodeChallengeMethodS256 = "S256"
	maxFailedAttempts       = 3
)

type AuthorizeRequest struct {
	ID                  SessionID `json:"id"  validate:"required,uuid"`
	CreatedAt           time.Time `json:"created_at"  validate:"required"`
	CSRFToken           string    `json:"csrf_token"  validate:"required"`
	ClientID            ClientID  `json:"client_id"   validate:"required"`
	RedirectURI         string    `json:"redirect_uri"                    validate:"required,redirect_uri"`
	Scope               Scope     `json:"scope"`
	State               *string   `json:"state,omitempty"`
	Nonce               *string   `json:"nonce,omitempty"`
	CodeChallenge       *string   `json:"code_challenge,omitempty"        validate:"omitempty,len=43"`
	CodeChallengeMethod *string   `json:"code_challenge_method,omitempty" validate:"required_with=CodeChallenge,omitempty,oneof=S256"`
	FailedAttempts      int       `json:"failed_attempts"`
}

// AuthorizeRequestArgs carries raw HTTP input into NewAuthorizeRequest.
// Primitive strings are used here — the factory validates and converts them.
type AuthorizeRequestArgs struct {
	ClientID            string
	RedirectURI         string
	Scope               string
	State               *string
	Nonce               *string
	CodeChallenge       *string
	CodeChallengeMethod *string
}

func NewAuthorizeRequest(args AuthorizeRequestArgs) (*AuthorizeRequest, error) {
	clientID, err := NewClientID(args.ClientID)
	if err != nil {
		return nil, err
	}
	scope, err := NewScope(strings.Fields(args.Scope))
	if err != nil {
		return nil, err
	}
	csrfToken, err := generateCSRFToken()
	if err != nil {
		return nil, err
	}
	s := &AuthorizeRequest{
		ID:                  NewSessionID(),
		CreatedAt:           time.Now(),
		CSRFToken:           csrfToken,
		ClientID:            clientID,
		RedirectURI:         args.RedirectURI,
		Scope:               scope,
		State:               args.State,
		Nonce:               args.Nonce,
		CodeChallenge:       args.CodeChallenge,
		CodeChallengeMethod: args.CodeChallengeMethod,
	}

	return s, s.Validate()
}

func (s *AuthorizeRequest) RequestFail() {
	s.FailedAttempts++
}

func (s *AuthorizeRequest) IsLockedOut() bool {
	return s.FailedAttempts >= maxFailedAttempts
}

func (s *AuthorizeRequest) BuildRedirectURI(code string) string {
	u, _ := url.Parse(s.RedirectURI)
	q := u.Query()
	q.Set("code", code)
	if s.State != nil {
		q.Set("state", *s.State)
	}
	u.RawQuery = q.Encode()
	return u.String()
}

func generateCSRFToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func (s *AuthorizeRequest) Validate() error {
	if s.Scope.IsEmpty() {
		return errors.New("scope is required")
	}
	if !s.Scope.Contains(ScopeOpenID) {
		return errors.New("scope must include openid")
	}
	return corevalidator.ValidateStruct(s)
}
