package autherrors

import (
	"net/http"
	coreerror "sc/core/error"
	"sc/core/web"
)

// codeInfo is the single source of truth for how an internal error code is
// surfaced over HTTP: its status and, on OAuth2 endpoints, its RFC 6749 error
// code. Keeping both in one table stops the HTTP and OAuth2 mappings drifting.
type codeInfo struct {
	httpStatus int
	oauth2     string // RFC 6749 §5.2 code; empty for non-OAuth, internal codes
}

var codeRegistry = map[coreerror.ErrCode]codeInfo{
	InvalidArguments:           {http.StatusBadRequest, web.OAuth2InvalidRequest},
	InvalidAuthRequest:         {http.StatusBadRequest, web.OAuth2InvalidRequest},
	WeakPassword:               {http.StatusBadRequest, web.OAuth2InvalidRequest},
	UnsupportedResponseType:    {http.StatusBadRequest, web.OAuth2UnsupportedResponseType},
	UnsupportedGrantType:       {http.StatusBadRequest, web.OAuth2UnsupportedGrantType},
	UnsupportedScope:           {http.StatusBadRequest, web.OAuth2InvalidScope},
	MaxLoginAttemptsExceeded:   {http.StatusBadRequest, web.OAuth2InvalidGrant},
	AuthCodeNotFound:           {http.StatusBadRequest, web.OAuth2InvalidGrant},
	InvalidToken:               {http.StatusUnauthorized, web.OAuth2InvalidGrant},
	InvalidRefreshToken:        {http.StatusUnauthorized, web.OAuth2InvalidGrant},
	InvalidEmailOrPassword:     {http.StatusUnauthorized, web.OAuth2InvalidGrant},
	InvalidClient:              {http.StatusUnauthorized, web.OAuth2InvalidClient},
	PasswordResetTokenExpired:  {http.StatusUnauthorized, web.OAuth2InvalidGrant},
	PasswordResetTokenNotFound: {http.StatusNotFound, web.OAuth2InvalidRequest},
	EmailDuplicated:            {http.StatusConflict, web.OAuth2InvalidRequest},
}

// serverErrorCodes are internal failures: 500 status, server_error on OAuth2.
var serverErrorCodes = map[coreerror.ErrCode]struct{}{
	GenRandFailed:         {},
	GenTokenFailed:        {},
	GenRefreshTokenFailed: {},
	AuthCodeCreateFailed:  {},
	CreateUserFailed:      {},
	UpdateProfileFailed:   {},
	ResetPasswordFailed:   {},
}

// HTTPStatusFor maps an internal error code to its HTTP status, defaulting to
// 500 for internal/unmapped codes.
func HTTPStatusFor(code coreerror.ErrCode) int {
	if info, ok := codeRegistry[code]; ok {
		return info.httpStatus
	}
	return http.StatusInternalServerError
}

// OAuth2CodeFor maps an internal error code to its RFC 6749 §5.2 error string.
// Internal failures map to server_error; anything else defaults to
// invalid_request.
func OAuth2CodeFor(code coreerror.ErrCode) string {
	if info, ok := codeRegistry[code]; ok && info.oauth2 != "" {
		return info.oauth2
	}
	if _, ok := serverErrorCodes[code]; ok {
		return web.OAuth2ServerError
	}
	return web.OAuth2InvalidRequest
}
