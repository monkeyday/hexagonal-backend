package autherrors

import (
	coreerror "sc/core/error"
)

const (
	InvalidArguments           coreerror.ErrCode = 10001
	InvalidToken               coreerror.ErrCode = 10002
	InvalidRefreshToken        coreerror.ErrCode = 10003
	GenRandFailed              coreerror.ErrCode = 10004
	InvalidEmailOrPassword     coreerror.ErrCode = 10005
	GenTokenFailed             coreerror.ErrCode = 10006
	GenRefreshTokenFailed      coreerror.ErrCode = 10007
	UpdateProfileFailed        coreerror.ErrCode = 10008
	EmailDuplicated            coreerror.ErrCode = 10009
	CreateUserFailed           coreerror.ErrCode = 10010
	AuthCodeNotFound           coreerror.ErrCode = 10012
	UnsupportedResponseType    coreerror.ErrCode = 10013
	UnsupportedGrantType       coreerror.ErrCode = 10014
	PasswordResetTokenExpired  coreerror.ErrCode = 10015
	PasswordResetTokenNotFound coreerror.ErrCode = 10016
	WeakPassword               coreerror.ErrCode = 10017
	MaxLoginAttemptsExceeded   coreerror.ErrCode = 10018
	AuthCodeCreateFailed       coreerror.ErrCode = 10019
	UnsupportedScope           coreerror.ErrCode = 10020
	InvalidAuthRequest         coreerror.ErrCode = 10021
	ResetPasswordFailed        coreerror.ErrCode = 10022
	InvalidClient              coreerror.ErrCode = 10023
)

func NewErrInvalidEmailOrPassword() *coreerror.ErrorStruct {
	return coreerror.NewMsg(InvalidEmailOrPassword, "invalid email or password")
}

func NewErrInvalidUserArguments(err error) *coreerror.ErrorStruct {
	return coreerror.NewErr(InvalidArguments, err)
}

func NewErrInvalidToken() *coreerror.ErrorStruct {
	return coreerror.NewMsg(InvalidToken, "invalid token")
}

func NewErrInvalidRefreshToken() *coreerror.ErrorStruct {
	return coreerror.NewMsg(InvalidRefreshToken, "invalid refresh token")
}

func NewErrCreateUser(_ error) *coreerror.ErrorStruct {
	return coreerror.NewMsg(CreateUserFailed, "create user failed")
}

func NewErrEmailDuplicated() *coreerror.ErrorStruct {
	return coreerror.NewMsg(EmailDuplicated, "email already exists")
}

func NewErrUpdateProfile(_ error) *coreerror.ErrorStruct {
	return coreerror.NewMsg(UpdateProfileFailed, "update profile failed")
}

func NewErrUpdateProfileFindFailed(err error) *coreerror.ErrorStruct {
	return coreerror.NewErr(UpdateProfileFailed, err)
}

func NewErrAuthCodeNotFound() *coreerror.ErrorStruct {
	return coreerror.NewMsg(AuthCodeNotFound, "auth code not found")
}

func NewErrUnsupportedResponseType() *coreerror.ErrorStruct {
	return coreerror.NewMsg(UnsupportedResponseType, "unsupported_response_type")
}

func NewErrPasswordResetTokenExpired() *coreerror.ErrorStruct {
	return coreerror.NewMsg(PasswordResetTokenExpired, "password reset token has expired")
}

func NewErrPasswordResetTokenNotFound() *coreerror.ErrorStruct {
	return coreerror.NewMsg(PasswordResetTokenNotFound, "password reset token not found")
}

func NewErrInvalidRedirectURI() *coreerror.ErrorStruct {
	return coreerror.NewMsg(InvalidArguments, "client redirect_uri not valid")
}

func NewErrInvalidSession() *coreerror.ErrorStruct {
	return coreerror.NewMsg(InvalidArguments, "invalid session")
}

func NewErrMaxLoginAttemptsExceeded() *coreerror.ErrorStruct {
	return coreerror.NewMsg(MaxLoginAttemptsExceeded, "maximum login attempts exceeded")
}

func NewErrAuthCodeCreateFailed(_ error) *coreerror.ErrorStruct {
	return coreerror.NewMsg(AuthCodeCreateFailed, "failed to create authorization code")
}

func NewErrUnsupportedScope(err error) *coreerror.ErrorStruct {
	return coreerror.NewErr(UnsupportedScope, err)
}

func NewErrInvalidAuthRequest() *coreerror.ErrorStruct {
	return coreerror.NewMsg(InvalidAuthRequest, "invalid authorization request")
}

func NewErrInvalidGrant() *coreerror.ErrorStruct {
	return coreerror.NewMsg(InvalidArguments, "invalid_grant")
}

func NewErrInvalidClient() *coreerror.ErrorStruct {
	return coreerror.NewMsg(InvalidClient, "invalid_client")
}

func NewErrGenRefreshTokenFailed(err error) *coreerror.ErrorStruct {
	return coreerror.NewErr(GenRefreshTokenFailed, err)
}

func NewErrWeakPassword(err error) *coreerror.ErrorStruct {
	return coreerror.NewErr(WeakPassword, err)
}

func NewErrResetPasswordFailed(_ error) *coreerror.ErrorStruct {
	return coreerror.NewMsg(ResetPasswordFailed, "reset password failed")
}
