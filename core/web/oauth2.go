package web

import coreerror "sc/core/error"

// OAuth2ErrorFormatKey flags a request whose error responses must follow the
// RFC 6749 §5.2 shape ({"error","error_description"}) instead of the default
// {"msg","err_code"}. Set by middleware on the OAuth2 token/revoke/introspect
// endpoints and read by the HTTP responder.
const OAuth2ErrorFormatKey = "oauth2_error_format"

// RFC 6749 §5.2 / OIDC error codes.
const (
	OAuth2InvalidRequest          = "invalid_request"
	OAuth2InvalidClient           = "invalid_client"
	OAuth2InvalidGrant            = "invalid_grant"
	OAuth2UnauthorizedClient      = "unauthorized_client"
	OAuth2UnsupportedGrantType    = "unsupported_grant_type"
	OAuth2UnsupportedResponseType = "unsupported_response_type"
	OAuth2InvalidScope            = "invalid_scope"
	OAuth2ServerError             = "server_error"
)

// OAuth2Error is implemented by errors that carry an RFC 6749 error code. The
// HTTP responder renders these as an RFC 6749 §5.2 body on flagged routes.
type OAuth2Error interface {
	OAuth2Code() string
	OAuth2Description() string
}

// oauth2Error is a transport-level OAuth2 error, used where an error originates
// before the application layer runs (e.g. grant_type validation middleware).
type oauth2Error struct {
	status int
	code   string
	desc   string
}

// NewOAuth2Error builds an error carrying an explicit RFC 6749 error code and
// HTTP status. Use the OAuth2* code constants for code.
func NewOAuth2Error(status int, code, description string) error {
	return &oauth2Error{status: status, code: code, desc: description}
}

func (e *oauth2Error) Error() string             { return e.desc }
func (e *oauth2Error) HTTPStatus() int           { return e.status }
func (e *oauth2Error) OAuth2Code() string        { return e.code }
func (e *oauth2Error) OAuth2Description() string { return e.desc }

func (e *oauth2Error) Code() coreerror.ErrCode {
	if e.status == 401 {
		return coreerror.Unauthorized
	}
	return coreerror.BadRequest
}
