package mongorepo

import (
	"context"
	"fmt"
	"time"

	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"go.mongodb.org/mongo-driver/mongo/readpref"
)

type Config struct {
	Host       string `validate:"required"`
	Username   string `validate:"required"`
	Password   string `validate:"required"`
	AuthSource string `validate:"required"`
	Database   string `validate:"required"`

	MaxPoolSize            uint64
	Direct                 bool
	ServerSelectionTimeout time.Duration
}

type MongoClient struct {
	client *mongo.Client
	DB     *mongo.Database
}

func NewMongoClient(cfg Config) (*MongoClient, error) {
	if cfg.MaxPoolSize == 0 {
		cfg.MaxPoolSize = 100
	}
	if cfg.ServerSelectionTimeout == 0 {
		cfg.ServerSelectionTimeout = 10 * time.Second
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	clientOpts := options.Client().
		SetHosts([]string{cfg.Host}).
		SetAuth(options.Credential{
			Username:   cfg.Username,
			Password:   cfg.Password,
			AuthSource: cfg.AuthSource,
		}).
		SetServerSelectionTimeout(cfg.ServerSelectionTimeout).
		SetDirect(cfg.Direct).
		SetReadPreference(readpref.Primary()).
		SetMaxPoolSize(cfg.MaxPoolSize)

	client, err := mongo.Connect(ctx, clientOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to MongoDB: %w", err)
	}

	if err := client.Ping(ctx, nil); err != nil {
		_ = client.Disconnect(context.Background())
		return nil, fmt.Errorf("MongoDB ping failed: %w", err)
	}

	return &MongoClient{
		client: client,
		DB:     client.Database(cfg.Database),
	}, nil
}

func (m *MongoClient) Disconnect(ctx context.Context) error {
	return m.client.Disconnect(ctx)
}

func (m *MongoClient) WithTransaction(ctx context.Context, fn func(sessCtx mongo.SessionContext) (any, error)) (any, error) {
	s, err := m.client.StartSession()
	if err != nil {
		return nil, fmt.Errorf("failed to start session: %w", err)
	}
	defer s.EndSession(ctx)

	return s.WithTransaction(ctx, fn)
}
