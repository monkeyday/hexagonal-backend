package autherrors

import (
	coreerror "sc/core/error"
	"sc/core/web"
)

// OAuth2CodeFor maps an internal error code to its RFC 6749 §5.2 error string.
// Codes that cannot occur on an OAuth2 endpoint default to invalid_request;
// internal failures map to server_error.
func OAuth2CodeFor(code coreerror.ErrCode) string {
	switch code {
	case InvalidClient:
		return web.OAuth2InvalidClient
	case AuthCodeNotFound, InvalidToken, InvalidRefreshToken,
		InvalidEmailOrPassword, MaxLoginAttemptsExceeded:
		return web.OAuth2InvalidGrant
	case UnsupportedGrantType:
		return web.OAuth2UnsupportedGrantType
	case UnsupportedResponseType:
		return web.OAuth2UnsupportedResponseType
	case UnsupportedScope:
		return web.OAuth2InvalidScope
	case GenRandFailed, GenTokenFailed, GenRefreshTokenFailed,
		AuthCodeCreateFailed, CreateUserFailed, UpdateProfileFailed,
		ResetPasswordFailed:
		return web.OAuth2ServerError
	default:
		return web.OAuth2InvalidRequest
	}
}

// HTTPError wraps a mapped error so it carries both an HTTP status and an
// RFC 6749 error code. The responder renders the RFC body on OAuth2 routes and
// falls back to the default {"msg","err_code"} shape elsewhere.
type HTTPError struct {
	*coreerror.ErrorStruct
}

func (e HTTPError) OAuth2Code() string        { return OAuth2CodeFor(e.Code()) }
func (e HTTPError) OAuth2Description() string { return e.Error() }
