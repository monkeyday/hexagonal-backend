package define

import (
	"sc/core/cache"
	coremetrics "sc/core/metrics"
	"sc/core/uow"
	"sc/modules/auth/port"
)

type Dependencies struct {
	Cache                       cache.Cache
	UoW                         uow.UnitOfWork
	JWTSvc                      port.TokenService
	Metrics                     coremetrics.Recorder
	UserRepo                    port.UserRepository
	EmailSender                 port.EmailSender
	RefreshTokenRepo            port.RefreshTokenRepository
	ClientRegistry              port.ClientRegistry
	PostLogoutRedirectAllowlist []string
	ScopeAllowlist              []string
}
