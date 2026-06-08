package query

import (
	"context"
	"fmt"
	"slices"

	corecache "sc/core/cache"
	"sc/core/usecase"
	"sc/modules/auth/application/define"
	"sc/modules/auth/domain/entity"
	autherrors "sc/modules/auth/errors"
)

type GetAuthorizeQuery struct {
	ResponseType        string  `form:"response_type" validate:"required,oneof=code"`
	ClientID            string  `form:"client_id"     validate:"required"`
	RedirectURI         string  `form:"redirect_uri"  validate:"required,redirect_uri" normalize:"uri"`
	Scope               string  `form:"scope"         validate:"required,has_any_word=openid"`
	State               *string `form:"state" validate:"omitempty,max=1024"`
	Nonce               *string `form:"nonce" validate:"omitempty,max=1024"`
	CodeChallenge       *string `form:"code_challenge"        validate:"omitempty,len=43"`
	CodeChallengeMethod *string `form:"code_challenge_method" validate:"required_with=CodeChallenge,omitempty,oneof=S256"`
}

type GetAuthorizeUseCase struct {
	// redirectURIAllowlist stands in for a client registry.
	// TODO: replace with a ClientRepository once a client registry exists.
	cache                corecache.Cache
	redirectURIAllowlist map[string][]string
}

func NewGetAuthorizeUseCase(deps define.Dependencies) usecase.UseCase {
	return &GetAuthorizeUseCase{
		cache:                deps.Cache,
		redirectURIAllowlist: deps.RedirectURIAllowlist,
	}
}

func (uc *GetAuthorizeUseCase) Execute(ctx context.Context, query any) (any, error) {
	q := query.(*GetAuthorizeQuery)

	if !uc.isValidRedirectURI(q.ClientID, q.RedirectURI) {
		return nil, autherrors.NewErrInvalidRedirectURI()
	}

	// TODO: once a client registry exists, require code_challenge for public clients (PKCE mandatory).
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
		return nil, autherrors.NewErrInvalidAuthRequest()
	}
	if err := uc.cache.Set(ctx, fmt.Sprintf(define.AuthorizeRequestCacheKey, session.ID), session, new(entity.AuthorizeRequestTTL)); err != nil {
		return nil, err
	}

	return &define.GetAuthorizeResponse{SessionID: string(session.ID)}, nil
}

func (uc *GetAuthorizeUseCase) isValidRedirectURI(clientID, redirectURI string) bool {
	// TODO: replace with a client registry lookup once a client registry exists.
	return slices.Contains(uc.redirectURIAllowlist[clientID], redirectURI)
}
