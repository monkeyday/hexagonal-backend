package autherrors

import (
	coreerror "sc/core/error"
	"sc/core/web"
	"testing"
)

func TestOAuth2CodeFor(t *testing.T) {
	tests := []struct {
		name string
		code coreerror.ErrCode
		want string
	}{
		{"invalid client", InvalidClient, web.OAuth2InvalidClient},
		{"auth code not found", AuthCodeNotFound, web.OAuth2InvalidGrant},
		{"invalid refresh token", InvalidRefreshToken, web.OAuth2InvalidGrant},
		{"invalid email or password", InvalidEmailOrPassword, web.OAuth2InvalidGrant},
		{"max login attempts", MaxLoginAttemptsExceeded, web.OAuth2InvalidGrant},
		{"unsupported grant type", UnsupportedGrantType, web.OAuth2UnsupportedGrantType},
		{"unsupported response type", UnsupportedResponseType, web.OAuth2UnsupportedResponseType},
		{"unsupported scope", UnsupportedScope, web.OAuth2InvalidScope},
		{"gen token failed", GenTokenFailed, web.OAuth2ServerError},
		{"invalid arguments defaults to invalid_request", InvalidArguments, web.OAuth2InvalidRequest},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := OAuth2CodeFor(tc.code); got != tc.want {
				t.Errorf("OAuth2CodeFor(%d) = %q, want %q", tc.code, got, tc.want)
			}
		})
	}
}

func TestHTTPError_ImplementsOAuth2Error(t *testing.T) {
	e := HTTPError{ErrorStruct: coreerror.New(InvalidClient, 401, "client auth failed")}

	var _ web.OAuth2Error = e
	if e.OAuth2Code() != web.OAuth2InvalidClient {
		t.Errorf("OAuth2Code = %q, want invalid_client", e.OAuth2Code())
	}
	if e.OAuth2Description() != "client auth failed" {
		t.Errorf("OAuth2Description = %q, want %q", e.OAuth2Description(), "client auth failed")
	}
	if e.HTTPStatus() != 401 {
		t.Errorf("HTTPStatus = %d, want 401", e.HTTPStatus())
	}
}
