package auth

import (
	"context"
	"errors"
	"net/http"
	coreerror "sc/core/error"
	coremetrics "sc/core/metrics"
	"sc/core/usecase"
	"sc/modules/auth/adapter"
	"sc/modules/auth/application/command"
	"sc/modules/auth/application/define"
	"sc/modules/auth/application/query"
	autherrors "sc/modules/auth/errors"

	"github.com/gin-gonic/gin"
)

type Module struct {
	*usecase.Registry
	router       *adapter.Router
	failedLogins coremetrics.Counter
	tokensIssued coremetrics.Counter
}

func NewModule(deps define.Dependencies) *Module {
	rec := deps.Metrics
	if rec == nil {
		rec = coremetrics.NewNoopRecorder()
	}
	m := &Module{
		Registry:     usecase.NewRegistry(),
		failedLogins: rec.Counter(define.MetricFailedLogins),
		tokensIssued: rec.Counter(define.MetricTokensIssued),
	}
	m.registerUseCases(deps)
	m.router = adapter.NewRouter(m, deps.JWTSvc, deps.Cache)
	return m
}

func (m *Module) Dispatch(ctx context.Context, cmd any) (any, error) {
	result, err := m.Registry.Dispatch(ctx, cmd)
	m.observeMetrics(cmd, err)
	return result, err
}

func (m *Module) observeMetrics(cmd any, err error) {
	if err != nil {
		if e, ok := err.(interface{ Code() coreerror.ErrCode }); ok && e.Code() == autherrors.InvalidEmailOrPassword {
			m.failedLogins.Add(1)
		}
		return
	}
	switch cmd.(type) {
	case *command.ExchangeCodeCommand, *command.CreateAuthCodeCommand, *query.GetTokenQuery:
		m.tokensIssued.Add(1)
	}
}

func (m *Module) RegisterRoutes(r *gin.Engine) {
	m.router.RegisterRoutes(r)
}

func (m *Module) MapHTTPError(err error) error {
	if err == nil {
		return nil
	}
	var e coreerror.Error
	ok := errors.As(err, &e)
	if !ok {
		return err
	}
	if hs, ok := err.(interface{ HTTPStatus() int }); ok && hs.HTTPStatus() != 0 {
		return autherrors.HTTPError{ErrorStruct: coreerror.NewErrorStruct(e.Code(), hs.HTTPStatus(), err)}
	}
	return autherrors.HTTPError{ErrorStruct: coreerror.NewErrorStruct(e.Code(), httpStatusMapper(e.Code()), err)}
}

func (m *Module) registerUseCases(deps define.Dependencies) {
	m.Register(command.CreateUserCommand{}, command.NewCreateUserUseCase(deps))
	m.Register(command.CreateAuthCodeCommand{}, command.NewCreateAuthCodeUseCase(deps))
	m.Register(command.RevokeTokenCommand{}, command.NewRevokeTokenUseCase(deps))
	m.Register(command.UpdateProfileCommand{}, command.NewUpdateProfileUseCase(deps))
	m.Register(command.RefreshTokenCommand{}, command.NewRefreshTokenUseCase(deps))
	m.Register(command.ExchangeCodeCommand{}, command.NewExchangeCodeUseCase(deps))
	m.Register(command.LogoutCommand{}, command.NewLogoutUseCase(deps))
	m.Register(command.ForgotPasswordCommand{}, command.NewForgotPasswordUseCase(deps))
	m.Register(command.ResetPasswordCommand{}, command.NewResetPasswordUseCase(deps))
	m.Register(query.GetDiscoveryQuery{}, query.NewGetDiscoveryUseCase(deps))
	m.Register(query.GetAuthorizeQuery{}, query.NewGetAuthorizeUseCase(deps))
	m.Register(query.GetSignInQuery{}, query.NewGetSignInUseCase(deps))
	m.Register(query.GetTokenQuery{}, query.NewGetTokenUseCase(deps))
	m.Register(query.GetProfileQuery{}, query.NewGetProfileUseCase(deps))
	m.Register(query.GetJWKSQuery{}, query.NewGetJWKSUseCase(deps))
	m.Register(query.IntrospectTokenQuery{}, query.NewIntrospectTokenUseCase(deps))
}

func httpStatusMapper(code coreerror.ErrCode) int {
	switch code {
	case autherrors.InvalidArguments,
		autherrors.WeakPassword,
		autherrors.UnsupportedResponseType,
		autherrors.UnsupportedGrantType,
		autherrors.MaxLoginAttemptsExceeded,
		autherrors.InvalidAuthRequest:
		return http.StatusBadRequest
	case autherrors.InvalidToken,
		autherrors.InvalidRefreshToken,
		autherrors.InvalidEmailOrPassword,
		autherrors.InvalidClient,
		autherrors.PasswordResetTokenExpired:
		return http.StatusUnauthorized
	case autherrors.AuthCodeNotFound:
		return http.StatusBadRequest
	case autherrors.PasswordResetTokenNotFound:
		return http.StatusNotFound
	case autherrors.EmailDuplicated:
		return http.StatusConflict
	default:
		return http.StatusInternalServerError
	}
}
