package entity

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"time"

	"sc/core/random"
	"sc/core/validator"
)

const AuthCodeTTL = 5 * time.Minute

type AuthCode struct {
	Code                string
	UserID              UserID
	ClientID            *ClientID
	RedirectURI         string
	Scope               Scope
	Nonce               *string
	CodeChallenge       *string
	CodeChallengeMethod *string
	ExpiresAt           time.Time
}

// AuthCodeArgs carries already-validated domain types into NewAuthCode.
// UserID and ClientID are typed because they always come from a validated AuthorizeRequest.
type AuthCodeArgs struct {
	UserID              UserID
	ClientID            ClientID
	RedirectURI         string
	Scope               Scope
	Nonce               *string
	CodeChallenge       *string
	CodeChallengeMethod *string
}

func NewAuthCode(args AuthCodeArgs) (*AuthCode, error) {
	code, err := generateCode()
	if err != nil {
		return nil, err
	}
	a := &AuthCode{
		Code:                code,
		UserID:              args.UserID,
		ClientID:            new(args.ClientID),
		RedirectURI:         args.RedirectURI,
		Scope:               args.Scope,
		Nonce:               args.Nonce,
		CodeChallenge:       args.CodeChallenge,
		CodeChallengeMethod: args.CodeChallengeMethod,
		ExpiresAt:           time.Now().Add(AuthCodeTTL),
	}

	return a, a.Validate()
}

func generateCode() (string, error) {
	return random.Token()
}

func (a *AuthCode) IsExpired() bool {
	return time.Now().After(a.ExpiresAt)
}

func (a *AuthCode) IsValid(clientID, redirectURI, verifier string) bool {
	return !a.IsExpired() &&
		a.matchesClient(clientID) &&
		a.matchesRedirectURI(redirectURI) &&
		a.verifyCodeVerifier(verifier) == nil
}

func (a *AuthCode) matchesClient(clientID string) bool {
	return *a.ClientID == ClientID(clientID)
}

func (a *AuthCode) matchesRedirectURI(redirectURI string) bool {
	return a.RedirectURI == redirectURI
}

func (a *AuthCode) verifyCodeVerifier(verifier string) error {
	if a.CodeChallenge == nil {
		return nil
	}
	if verifier == "" {
		return errors.New("code_verifier required")
	}
	method := CodeChallengeMethodS256
	if a.CodeChallengeMethod != nil {
		method = *a.CodeChallengeMethod
	}
	if method != CodeChallengeMethodS256 {
		return errors.New("unsupported code_challenge_method")
	}
	h := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(h[:])
	if subtle.ConstantTimeCompare([]byte(challenge), []byte(*a.CodeChallenge)) != 1 {
		return errors.New("code_verifier mismatch")
	}
	return nil
}

func (a *AuthCode) Validate() error {
	if a.Scope.IsEmpty() {
		return errors.New("scope is required")
	}
	return validator.ValidateStruct(a)
}
