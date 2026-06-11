package dependencies

import (
	"context"
	"fmt"
	"sc/cmd/auth/config"
	corecache "sc/core/cache"
	"sc/core/uow"
	"sc/infrastructure/cache"
	"sc/infrastructure/jwt"
	filerepo "sc/infrastructure/repository/file"
	mongorepo "sc/infrastructure/repository/mongo"
	infrasmtp "sc/infrastructure/smtp"

	"github.com/rs/zerolog/log"
)

type Deps struct {
	Config            *config.Settings
	JWTService        *jwt.JWTService
	MongoClient       *mongorepo.MongoClient
	UnitOfWork        uow.UnitOfWork
	Cache             corecache.Cache
	FileStore         *filerepo.FileStore
	RefreshTokenStore *filerepo.FileStore
	SMTPClient        *infrasmtp.Client
}

func NewDeps(cfg *config.Settings) Deps {
	deps := Deps{Config: cfg}
	jwtSvc, err := jwt.NewJWTService(cfg.JWT)
	if err != nil {
		log.Err(err).Msg("Failed to initialize JWT service")
		panic(err)
	}
	deps.JWTService = jwtSvc

	c, err := selectCache(cfg.Redis.Addr, func() (corecache.Cache, error) { return cache.NewRedisCache(cfg.Redis) })
	if err != nil {
		log.Err(err).Msg("Failed to initialize cache")
		panic(err)
	}
	deps.Cache = c

	if cfg.SMTP.Host != "" {
		deps.SMTPClient = infrasmtp.NewClient(cfg.SMTP.Addr(), cfg.SMTP.From)
	}

	switch cfg.RepositoryType {
	case "mongo":
		mongoClient, err := mongorepo.NewMongoClient(cfg.Mongo)
		if err != nil {
			log.Err(err).Str("host", cfg.Mongo.Host).Str("database", cfg.Mongo.Database).Msg("Failed to connect to MongoDB")
			panic(err)
		}
		deps.MongoClient = mongoClient
		deps.UnitOfWork = mongorepo.NewUnitOfWork(mongoClient)

	default: // "file"
		fileStore, err := filerepo.NewFileStore(cfg.FileRepository.Dir, cfg.FileRepository.UserFileName)
		if err != nil {
			log.Err(err).Interface("config", cfg.FileRepository).Msg("Failed to initialize file store")
			panic(err)
		}
		deps.FileStore = fileStore

		rtStore, err := filerepo.NewFileStore(cfg.FileRepository.Dir, cfg.FileRepository.RefreshTokenFileName)
		if err != nil {
			log.Err(err).Msg("Failed to initialize refresh token file store")
			panic(err)
		}
		deps.RefreshTokenStore = rtStore
	}

	return deps
}

// selectCache fails closed: a deployment that configured Redis must not
// silently run on per-replica memory — that would split the rate limiter,
// the JTI blacklist, and auth sessions across replicas. Memory cache is the
// default only when Redis is not configured at all.
func selectCache(redisAddr string, newRedis func() (corecache.Cache, error)) (corecache.Cache, error) {
	if redisAddr == "" {
		return cache.NewMemoryCache(), nil
	}
	r, err := newRedis()
	if err != nil {
		return nil, fmt.Errorf("redis configured at %s but unreachable: %w", redisAddr, err)
	}
	return r, nil
}

func (d Deps) Cleanup(ctx context.Context) {
	if d.MongoClient != nil {
		if err := d.MongoClient.Disconnect(ctx); err != nil {
			log.Printf("error disconnecting MongoDB: %v", err)
		}
	}
	if d.JWTService != nil {
		d.JWTService.Close()
	}
	if c, ok := d.Cache.(interface{ Close() error }); ok {
		if err := c.Close(); err != nil {
			log.Printf("error closing cache: %v", err)
		}
	}
	if d.SMTPClient != nil {
		if err := d.SMTPClient.Close(); err != nil {
			log.Printf("error closing SMTP client: %v", err)
		}
	}
}
