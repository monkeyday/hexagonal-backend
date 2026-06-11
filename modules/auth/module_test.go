package auth

import (
	"net/http"
	"testing"

	coreerror "sc/core/error"
	autherrors "sc/modules/auth/errors"
)

func TestHTTPStatusMapper(t *testing.T) {
	tests := []struct {
		name string
		code coreerror.ErrCode
		want int
	}{
		{"invalid arguments", autherrors.InvalidArguments, http.StatusBadRequest},
		{"weak password", autherrors.WeakPassword, http.StatusBadRequest},
		{"unsupported response type", autherrors.UnsupportedResponseType, http.StatusBadRequest},
		{"unsupported grant type", autherrors.UnsupportedGrantType, http.StatusBadRequest},
		{"max login attempts exceeded", autherrors.MaxLoginAttemptsExceeded, http.StatusBadRequest},
		{"invalid auth request", autherrors.InvalidAuthRequest, http.StatusBadRequest},
		{"auth code not found", autherrors.AuthCodeNotFound, http.StatusBadRequest},
		{"invalid token", autherrors.InvalidToken, http.StatusUnauthorized},
		{"invalid refresh token", autherrors.InvalidRefreshToken, http.StatusUnauthorized},
		{"invalid email or password", autherrors.InvalidEmailOrPassword, http.StatusUnauthorized},
		{"password reset token expired", autherrors.PasswordResetTokenExpired, http.StatusUnauthorized},
		{"password reset token not found", autherrors.PasswordResetTokenNotFound, http.StatusNotFound},
		{"email duplicated", autherrors.EmailDuplicated, http.StatusConflict},
		{"unknown code falls back to internal error", autherrors.GenRandFailed, http.StatusInternalServerError},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := httpStatusMapper(tt.code); got != tt.want {
				t.Errorf("httpStatusMapper(%d) = %d, want %d", tt.code, got, tt.want)
			}
		})
	}
}

func TestMapHTTPErrorPreservesExplicitHTTPStatus(t *testing.T) {
	m := &Module{}
	err := coreerror.NewErrorStruct(11002, http.StatusNotFound, coreerror.ErrNotFound)

	got := m.MapHTTPError(err)
	httpErr, ok := got.(interface{ HTTPStatus() int })
	if !ok {
		t.Fatalf("MapHTTPError returned %T, want HTTPStatus", got)
	}
	if httpErr.HTTPStatus() != http.StatusNotFound {
		t.Fatalf("HTTPStatus = %d, want %d", httpErr.HTTPStatus(), http.StatusNotFound)
	}
}
