package query

import (
	"context"
	"fmt"
	"strings"

	corecache "sc/core/cache"
	"sc/core/usecase"
	"sc/core/web"
	"sc/modules/auth/application/define"
	"sc/modules/auth/domain/entity"
	autherrors "sc/modules/auth/errors"
	"sc/modules/auth/port"
)

const (
	responseTypeCode    = "code"
	codeChallengeLength = 43
	maxStateNonceLen    = 1024
)

// Only client_id and redirect_uri are validated at the binding layer: per
// RFC 6749 §4.1.2.1 they must be valid before any other error may be redirected
// back to the client. The remaining parameters are validated inside Execute so
// their failures can be returned as redirect-errors.
type GetAuthorizeQuery struct {
	ResponseType        string  `form:"response_type"`
	ClientID            string  `form:"client_id"     validate:"required"`
	RedirectURI         string  `form:"redirect_uri"  validate:"required,redirect_uri" normalize:"uri"`
	Scope               string  `form:"scope"`
	State               *string `form:"state"`
	Nonce               *string `form:"nonce"`
	CodeChallenge       *string `form:"code_challenge"`
	CodeChallengeMethod *string `form:"code_challenge_method"`
}

type GetAuthorizeUseCase struct {
	cache   corecache.Cache
	clients port.ClientRegistry
}

func NewGetAuthorizeUseCase(deps define.Dependencies) usecase.UseCase {
	return &GetAuthorizeUseCase{
		cache:   deps.Cache,
		clients: deps.ClientRegistry,
	}
}

func (uc *GetAuthorizeUseCase) Execute(ctx context.Context, query any) (any, error) {
	q := query.(*GetAuthorizeQuery)

	// The client and its redirect_uri must be registered before any error may be
	// redirected back (RFC 6749 §4.1.2.1) — an unregistered URI is reported
	// directly, so the endpoint cannot be used as an open redirector.
	client, err := uc.clients.FindByID(ctx, entity.DefaultTenantID, entity.ClientID(q.ClientID))
	if err != nil {
		return nil, err
	}
	if client == nil || !client.AllowsRedirectURI(q.RedirectURI) {
		return nil, autherrors.NewErrInvalidRedirectURI()
	}

	if errCode := uc.protocolError(q, client); errCode != "" {
		return define.NewAuthorizeErrorRedirect(q.RedirectURI, errCode, q.State), nil
	}

	session, err := entity.NewAuthorizeRequest(entity.AuthorizeRequestArgs{
		ClientID:            q.ClientID,
		RedirectURI:         q.RedirectURI,
		Scope:               q.Scope,
		State:               q.State,
		Nonce:               q.Nonce,
		CodeChallenge:       q.CodeChallenge,
		CodeChallengeMethod: q.CodeChallengeMethod,
	})
	if err != nil {
		return define.NewAuthorizeErrorRedirect(q.RedirectURI, web.OAuth2InvalidRequest, q.State), nil
	}
	if err := uc.cache.Set(ctx, fmt.Sprintf(define.AuthorizeRequestCacheKey, session.ID), session, new(entity.AuthorizeRequestTTL)); err != nil {
		return nil, err
	}

	return &define.GetAuthorizeResponse{SessionID: string(session.ID)}, nil
}

// protocolError validates the request now that redirect_uri is registered and
// returns the RFC 6749 error code to redirect with (empty when well-formed).
// These checks mirror entity.AuthorizeRequest's own validation but distinguish
// the specific error code each failure must report.
func (uc *GetAuthorizeUseCase) protocolError(q *GetAuthorizeQuery, client *entity.Client) string {
	switch {
	case q.ResponseType == "":
		return web.OAuth2InvalidRequest
	case q.ResponseType != responseTypeCode:
		return web.OAuth2UnsupportedResponseType
	}

	scope, err := entity.NewScope(strings.Fields(q.Scope))
	if err != nil || !scope.Contains(entity.ScopeOpenID) {
		return web.OAuth2InvalidScope
	}

	// PKCE (S256) is mandatory for public clients.
	if !validPKCE(q) || (client.IsPublic() && q.CodeChallenge == nil) {
		return web.OAuth2InvalidRequest
	}

	if tooLong(q.State) || tooLong(q.Nonce) {
		return web.OAuth2InvalidRequest
	}
	return ""
}

// validPKCE reports whether the PKCE parameters are internally consistent: a
// challenge must be 43 chars with method S256, and a method without a challenge
// is malformed.
func validPKCE(q *GetAuthorizeQuery) bool {
	if q.CodeChallenge == nil {
		return q.CodeChallengeMethod == nil
	}
	if len(*q.CodeChallenge) != codeChallengeLength {
		return false
	}
	return q.CodeChallengeMethod != nil && *q.CodeChallengeMethod == entity.CodeChallengeMethodS256
}

func tooLong(s *string) bool {
	return s != nil && len(*s) > maxStateNonceLen
}
