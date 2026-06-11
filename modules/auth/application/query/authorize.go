package query

import (
	"context"
	"fmt"

	corecache "sc/core/cache"
	"sc/core/usecase"
	"sc/modules/auth/application/define"
	"sc/modules/auth/domain/entity"
	autherrors "sc/modules/auth/errors"
	"sc/modules/auth/port"
)

const responseTypeCode = "code"

type GetAuthorizeQuery struct {
	ResponseType        string  `form:"response_type" validate:"required"`
	ClientID            string  `form:"client_id"     validate:"required"`
	RedirectURI         string  `form:"redirect_uri"  validate:"required,redirect_uri" normalize:"uri"`
	Scope               string  `form:"scope"         validate:"required,has_any_word=openid"`
	State               *string `form:"state" validate:"omitempty,max=1024"`
	Nonce               *string `form:"nonce" validate:"omitempty,max=1024"`
	CodeChallenge       *string `form:"code_challenge"        validate:"omitempty,len=43"`
	CodeChallengeMethod *string `form:"code_challenge_method" validate:"required_with=CodeChallenge,omitempty,oneof=S256"`
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

	if q.ResponseType != responseTypeCode {
		return nil, autherrors.NewErrUnsupportedResponseType()
	}

	client, err := uc.clients.FindByID(ctx, entity.DefaultTenantID, entity.ClientID(q.ClientID))
	if err != nil {
		return nil, err
	}
	if client == nil || !client.AllowsRedirectURI(q.RedirectURI) {
		return nil, autherrors.NewErrInvalidRedirectURI()
	}

	// TODO(#1): require code_challenge when client.IsPublic() (PKCE mandatory for public clients).
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
