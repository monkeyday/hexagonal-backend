package define

import (
	"sc/core/cache"
	"sc/core/event"
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
	GrantRepo                   port.GrantRepository
	ClientRegistry              port.ClientRegistry
	EventPublisher              event.Publisher
	PostLogoutRedirectAllowlist []string
	ScopeAllowlist              []string
}
