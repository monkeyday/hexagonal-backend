package define

import (
	"sc/core/cache"
	coremetrics "sc/core/metrics"
	"sc/core/uow"
	"sc/modules/auth/port"
)

type Dependencies struct {
	Cache            cache.Cache
	UoW              uow.UnitOfWork
	JWTSvc           port.TokenService
	Metrics          coremetrics.Recorder
	UserRepo         port.UserRepository
	EmailSender      port.EmailSender
	RefreshTokenRepo port.RefreshTokenRepository
	// TODO: replace with a ClientRepository once a client registry exists.
	// The registry should store client type (public/confidential), allowed redirect URIs,
	// allowed grant types, and client secret for confidential clients.
	RedirectURIAllowlist        map[string][]string
	PostLogoutRedirectAllowlist []string
	ScopeAllowlist              []string
}
