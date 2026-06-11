package command

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/rs/zerolog/log"

	corecache "sc/core/cache"
	coreerror "sc/core/error"
	coremetrics "sc/core/metrics"
	"sc/core/usecase"
	"sc/modules/auth/application/define"
	"sc/modules/auth/application/service"
	"sc/modules/auth/domain/entity"
	autherrors "sc/modules/auth/errors"
	"sc/modules/auth/port"
)

type RevokeTokenCommand struct {
	CallerID          string  `ctx:"user_id"`
	ClientID          string  `form:"client_id" json:"client_id"`
	ClientSecret      string  `form:"client_secret" json:"client_secret"`
	BasicClientID     string  `ctx:"basic_client_id"`
	BasicClientSecret string  `ctx:"basic_client_secret"`
	Token             string  `form:"token" json:"token" validate:"required"`
	TokenTypeHint     *string `form:"token_type_hint" json:"token_type_hint" validate:"omitempty,oneof=access_token refresh_token"`
}

type RevokeTokenUseCase struct {
	jwtSvc              port.TokenParser
	cache               corecache.Cache
	refreshTokenRepo    port.RefreshTokenRepository
	revocationsCounter  coremetrics.Counter
	clientAuthenticator *service.ClientAuthenticator
}

func NewRevokeTokenUseCase(deps define.Dependencies) usecase.UseCase {
	rec := deps.Metrics
	if rec == nil {
		rec = coremetrics.NewNoopRecorder()
	}
	return &RevokeTokenUseCase{
		jwtSvc:              deps.JWTSvc,
		cache:               deps.Cache,
		refreshTokenRepo:    deps.RefreshTokenRepo,
		revocationsCounter:  rec.Counter(define.MetricTokenRevocations),
		clientAuthenticator: service.NewClientAuthenticator(deps.ClientRegistry),
	}
}

// Execute revokes the submitted token. token_type_hint is advisory per RFC 7009 §2.1:
// if lookup under the hinted type misses, the server MUST extend its search to other types.
func (uc *RevokeTokenUseCase) Execute(ctx context.Context, cmd any) (any, error) {
	c := cmd.(*RevokeTokenCommand)

	// RFC 7009 §2.1: callers without a bearer token authenticate as clients;
	// public clients are identified by registered client_id (possession of
	// the token itself is the capability — revocation can only destroy it).
	// Bearer callers keep subject-scoped ownership checks below.
	if c.CallerID == "" {
		if c.ClientID == "" && c.BasicClientID == "" {
			return nil, autherrors.NewErrInvalidClient()
		}
		if _, err := uc.clientAuthenticator.Authenticate(ctx, service.ClientCredentials{
			ClientID:      c.ClientID,
			FormSecret:    c.ClientSecret,
			BasicClientID: c.BasicClientID,
			BasicSecret:   c.BasicClientSecret,
		}); err != nil {
			return nil, autherrors.NewErrInvalidClient()
		}
	}

	isAccessTokenHint := c.TokenTypeHint != nil && *c.TokenTypeHint == "access_token"

	if isAccessTokenHint {
		// Try access-token path first, then fall through to RT if not a caller-owned AT.
		revoked, err := uc.blacklistAccessToken(ctx, c.Token, c.CallerID)
		if err != nil || revoked {
			return nil, err
		}

		rt, lookupErr := uc.refreshTokenRepo.FindByTokenHash(ctx, entity.Hash(c.Token))
		if lookupErr == nil {
			if c.CallerID != "" && rt.UserID != entity.UserID(c.CallerID) {
				return nil, nil // RFC 7009 §2.2: wrong owner → treat as unknown
			}
			return nil, uc.revokeConfirmedRefreshToken(ctx, entity.Hash(c.Token))
		}
		if !errors.Is(lookupErr, coreerror.ErrNotFound) {
			log.Warn().Err(lookupErr).Msg("revoke: refresh token lookup failed after access-token path")
			return nil, lookupErr
		}
		return nil, nil // neither path found the token
	}

	// RT hint or no hint: try RT first, then AT per RFC 7009 §2.1.
	rt, lookupErr := uc.refreshTokenRepo.FindByTokenHash(ctx, entity.Hash(c.Token))
	switch {
	case lookupErr == nil:
		if c.CallerID != "" && rt.UserID != entity.UserID(c.CallerID) {
			return nil, nil // RFC 7009 §2.2: wrong owner → treat as unknown
		}
		return nil, uc.revokeConfirmedRefreshToken(ctx, entity.Hash(c.Token))

	case errors.Is(lookupErr, coreerror.ErrNotFound):
		// Not in RT store → extend search to AT per RFC 7009 §2.1.
		_, err := uc.blacklistAccessToken(ctx, c.Token, c.CallerID)
		return nil, err

	default:
		// RT store backend error. Fall through to AT; surface the storage error if AT
		// also doesn't confirm the token was revoked.
		log.Warn().Err(lookupErr).Msg("revoke: refresh token lookup failed, attempting access-token revocation")
		revoked, atErr := uc.blacklistAccessToken(ctx, c.Token, c.CallerID)
		if atErr != nil {
			return nil, atErr
		}
		if !revoked {
			return nil, lookupErr
		}
		return nil, nil
	}
}

// revokeConfirmedRefreshToken revokes a token already confirmed as caller-owned.
// ErrNotFound means it was revoked between FindByTokenHash and now — treat as success.
func (uc *RevokeTokenUseCase) revokeConfirmedRefreshToken(ctx context.Context, tokenHash string) error {
	if err := uc.refreshTokenRepo.RevokeByTokenHash(ctx, tokenHash); err != nil {
		if errors.Is(err, coreerror.ErrNotFound) {
			return nil
		}
		return err
	}
	uc.revocationsCounter.Add(1)
	log.Info().Str("token_type", "refresh_token").Msg("token revoked")
	return nil
}

// blacklistAccessToken adds the token's JTI to the revocation cache.
// Returns (true, nil) only when the token was successfully blacklisted.
// Returns (false, nil) for unrecognised, expired, or wrong-owner tokens (RFC 7009 §2.2).
func (uc *RevokeTokenUseCase) blacklistAccessToken(ctx context.Context, token, callerID string) (bool, error) {
	claims, err := uc.jwtSvc.ParseJWT(token)
	if err != nil || claims == nil || claims.ID == "" {
		return false, nil
	}
	// Bearer callers may only revoke their own tokens (RFC 7009 §2.2);
	// client-authenticated callers (empty callerID) revoke any presented token.
	if callerID != "" && claims.Subject != callerID {
		return false, nil
	}
	if claims.IsExpired() {
		return false, nil
	}
	if err := uc.cache.Set(ctx, fmt.Sprintf(define.BlacklistCacheKey, claims.ID), true, new(time.Until(*claims.ExpiresAt))); err != nil {
		return false, err
	}
	uc.revocationsCounter.Add(1)
	log.Info().Str("user_id", claims.Subject).Msg("access token revoked")
	return true, nil
}
