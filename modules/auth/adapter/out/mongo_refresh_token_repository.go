package adapter

import (
	"context"
	"fmt"
	"time"

	coreerror "sc/core/error"
	mongorepo "sc/infrastructure/repository/mongo"
	"sc/modules/auth/domain/entity"
	"sc/modules/auth/port"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

const refreshTokensCollection = "refresh_tokens"

var _ port.RefreshTokenRepository = (*MongoRefreshTokenRepository)(nil)

type MongoRefreshTokenRepository struct {
	col *mongo.Collection
}

func NewMongoRefreshTokenRepository(client *mongorepo.MongoClient) (*MongoRefreshTokenRepository, error) {
	col := client.DB.Collection(refreshTokensCollection)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_, err := col.Indexes().CreateMany(ctx, []mongo.IndexModel{
		{
			Keys:    bson.D{{Key: "token_hash", Value: 1}},
			Options: options.Index().SetUnique(true),
		},
		{
			Keys: bson.D{
				{Key: "user_id", Value: 1},
				{Key: "revoked_at", Value: 1},
			},
		},
		{
			Keys:    bson.D{{Key: "expires_at", Value: 1}},
			Options: options.Index().SetExpireAfterSeconds(0),
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create refresh token indexes: %w", err)
	}

	return &MongoRefreshTokenRepository{col: col}, nil
}

func (r *MongoRefreshTokenRepository) Save(ctx context.Context, rt *entity.RefreshToken) error {
	doc := rtToDoc(rt)
	filter := bson.D{{Key: "_id", Value: doc.ID}}
	update := bson.D{{Key: "$set", Value: doc}}
	_, err := r.col.UpdateOne(ctx, filter, update, options.Update().SetUpsert(true))
	return err
}

func (r *MongoRefreshTokenRepository) FindByTokenHash(ctx context.Context, tokenHash string) (*entity.RefreshToken, error) {
	var doc refreshTokenDoc
	err := r.col.FindOne(ctx, bson.D{{Key: "token_hash", Value: tokenHash}}).Decode(&doc)
	if err == mongo.ErrNoDocuments {
		return nil, coreerror.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return rtToEntity(&doc)
}

func (r *MongoRefreshTokenRepository) RevokeByTokenHash(ctx context.Context, tokenHash string) error {
	now := time.Now()
	filter := bson.D{
		{Key: "token_hash", Value: tokenHash},
		{Key: "revoked_at", Value: nil},
		{Key: "expires_at", Value: bson.D{{Key: "$gt", Value: now}}},
	}
	update := bson.D{{Key: "$set", Value: bson.D{{Key: "revoked_at", Value: now}}}}
	result, err := r.col.UpdateOne(ctx, filter, update)
	if err != nil {
		return err
	}
	if result.MatchedCount == 0 {
		return coreerror.ErrNotFound
	}
	return nil
}

func (r *MongoRefreshTokenRepository) RevokeAllForUser(ctx context.Context, userID entity.UserID) error {
	filter := bson.D{{Key: "user_id", Value: string(userID)}, {Key: "revoked_at", Value: nil}}
	update := bson.D{{Key: "$set", Value: bson.D{{Key: "revoked_at", Value: time.Now()}}}}
	_, err := r.col.UpdateMany(ctx, filter, update)
	return err
}
