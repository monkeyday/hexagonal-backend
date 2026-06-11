package wire

import (
	"fmt"
	"sc/cmd/auth/config"
	"sc/cmd/auth/dependencies"
	coreuow "sc/core/uow"
	inframetrics "sc/infrastructure/metrics"
	"sc/modules/auth"
	adapterout "sc/modules/auth/adapter/out"
	"sc/modules/auth/application/define"
	"sc/modules/auth/domain/entity"
	"sc/modules/auth/port"
)

func Auth(cfg *config.Settings, deps dependencies.Deps) *auth.Module {
	return auth.NewModule(buildAuthDeps(cfg, deps))
}

func buildAuthDeps(cfg *config.Settings, deps dependencies.Deps) define.Dependencies {
	var userRepo port.UserRepository
	if cfg.RepositoryType == "mongo" {
		r, err := adapterout.NewMongoUserRepository(deps.MongoClient)
		if err != nil {
			panic(fmt.Sprintf("failed to initialize user repository: %v", err))
		}
		userRepo = r
	} else {
		r, err := adapterout.NewUserRepository(deps.FileStore, buildSeedUsers())
		if err != nil {
			panic(fmt.Sprintf("failed to initialize user repository: %v", err))
		}
		userRepo = r
	}

	var refreshTokenRepo port.RefreshTokenRepository
	if cfg.RepositoryType == "mongo" {
		r, err := adapterout.NewMongoRefreshTokenRepository(deps.MongoClient)
		if err != nil {
			panic(fmt.Sprintf("failed to initialize refresh token repository: %v", err))
		}
		refreshTokenRepo = r
	} else {
		r, err := adapterout.NewFileRefreshTokenRepository(deps.RefreshTokenStore)
		if err != nil {
			panic(fmt.Sprintf("failed to initialize refresh token repository: %v", err))
		}
		refreshTokenRepo = r
	}

	uow := deps.UnitOfWork
	if uow == nil {
		uow = &coreuow.NoopUnitOfWork{}
	}

	return define.Dependencies{
		Cache:                       deps.Cache,
		UoW:                         uow,
		JWTSvc:                      adapterout.NewJWTServiceAdapter(deps.JWTService),
		Metrics:                     inframetrics.NewExpvarRecorder(),
		UserRepo:                    userRepo,
		RefreshTokenRepo:            refreshTokenRepo,
		EmailSender:                 buildEmailSender(deps),
		ClientRegistry:              buildClientRegistry(cfg.OAuth.Client),
		PostLogoutRedirectAllowlist: cfg.OAuth.PostLogoutRedirectAllowlist,
		ScopeAllowlist:              cfg.OAuth.ScopeAllowlist,
	}
}

func buildClientRegistry(c config.ClientConfig) port.ClientRegistry {
	authMethod, err := entity.ParseClientAuthMethod(c.AuthMethod)
	if err != nil {
		panic(fmt.Sprintf("invalid client configuration: %v", err))
	}
	grants := make([]entity.GrantType, 0, len(c.AllowedGrants))
	for _, raw := range c.AllowedGrants {
		g, err := entity.ParseGrantType(raw)
		if err != nil {
			panic(fmt.Sprintf("invalid client configuration: %v", err))
		}
		grants = append(grants, g)
	}
	client, err := entity.NewClient(entity.ClientArgs{
		ID:            c.ID,
		AuthMethod:    authMethod,
		Secret:        c.Secret,
		RedirectURIs:  c.RedirectURIs,
		AllowedGrants: grants,
	})
	if err != nil {
		panic(fmt.Sprintf("invalid client configuration: %v", err))
	}
	return adapterout.NewConfigClientRegistry(client)
}

func buildEmailSender(deps dependencies.Deps) port.EmailSender {
	if deps.SMTPClient != nil {
		return adapterout.NewSmtpEmailSender(deps.SMTPClient, deps.Config.AppBaseURL)
	}
	return adapterout.NewLogEmailSender()
}

func buildSeedUsers() map[string]*entity.User {
	users := make(map[string]*entity.User)
	for i := 1000; i < 1100; i++ {
		u, err := entity.NewUser(entity.UserArgs{
			Username:      fmt.Sprintf("test%d", i),
			Nickname:      fmt.Sprintf("test%d_nickname", i),
			Password:      "1qazXSW@",
			Email:         fmt.Sprintf("test%d@test.io", i),
			EmailVerified: i%2 == 0,
		})
		if err != nil {
			panic(fmt.Sprintf("buildSeedUsers: %v", err))
		}
		users[string(u.ID)] = u
	}
	return users
}
