package service

import (
	coreerror "sc/core/error"
	"sc/modules/auth/domain/entity"
	autherrors "sc/modules/auth/errors"
	"sc/modules/auth/port"
)

type TokenIssuanceService struct {
	issuer port.TokenIssuer
}

func NewTokenIssuanceService(issuer port.TokenIssuer) *TokenIssuanceService {
	return &TokenIssuanceService{issuer: issuer}
}

type IssueTokensArgs struct {
	User       *entity.User
	ClientID   entity.ClientID
	Nonce      string
	Scope      entity.Scope
	ExpireSecs int
}

func (s *TokenIssuanceService) IssueTokens(req IssueTokensArgs) (*entity.IssuedTokens, error) {
	accessToken, err := s.issuer.GenAccessToken(string(req.User.ID), req.Scope.String(), req.ExpireSecs)
	if err != nil {
		return nil, coreerror.NewErr(autherrors.GenTokenFailed, err)
	}

	rawRefreshToken, err := s.issuer.GenRefreshToken(string(req.User.ID))
	if err != nil {
		return nil, coreerror.NewErr(autherrors.GenRefreshTokenFailed, err)
	}

	var idToken string
	if req.Scope.Contains(entity.ScopeOpenID) {
		idToken, err = s.issuer.GenIDToken(port.IDTokenArgs{
			UserID:        string(req.User.ID),
			ClientID:      string(req.ClientID),
			Email:         req.User.Email,
			Nonce:         req.Nonce,
			EmailVerified: req.User.EmailVerified,
			ExpireSecs:    req.ExpireSecs,
		})
		if err != nil {
			return nil, coreerror.NewErr(autherrors.GenTokenFailed, err)
		}
	}

	return &entity.IssuedTokens{
		AccessToken:  accessToken,
		RefreshToken: rawRefreshToken,
		IDToken:      idToken,
		Scope:        req.Scope,
	}, nil
}
