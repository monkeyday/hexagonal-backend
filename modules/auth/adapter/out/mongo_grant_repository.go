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

const grantsCollection = "grants"

var _ port.GrantRepository = (*MongoGrantRepository)(nil)

type MongoGrantRepository struct {
	col *mongo.Collection
}

func NewMongoGrantRepository(client *mongorepo.MongoClient) (*MongoGrantRepository, error) {
	col := client.DB.Collection(grantsCollection)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_, err := col.Indexes().CreateMany(ctx, []mongo.IndexModel{
		{
			Keys:    bson.D{{Key: "expires_at", Value: 1}},
			Options: options.Index().SetExpireAfterSeconds(0),
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create grant indexes: %w", err)
	}

	return &MongoGrantRepository{col: col}, nil
}

func (r *MongoGrantRepository) Save(ctx context.Context, g *entity.Grant) error {
	doc := grantToDoc(g)
	filter := bson.D{{Key: "_id", Value: doc.ID}}
	update := bson.D{{Key: "$set", Value: doc}}
	_, err := r.col.UpdateOne(ctx, filter, update, options.Update().SetUpsert(true))
	return err
}

func (r *MongoGrantRepository) FindByID(ctx context.Context, grantID entity.GrantID) (*entity.Grant, error) {
	var doc grantDoc
	err := r.col.FindOne(ctx, bson.D{{Key: "_id", Value: string(grantID)}}).Decode(&doc)
	if err == mongo.ErrNoDocuments {
		return nil, coreerror.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return grantToEntity(&doc)
}

func (r *MongoGrantRepository) Revoke(ctx context.Context, grantID entity.GrantID, at time.Time) error {
	filter := bson.D{
		{Key: "_id", Value: string(grantID)},
		{Key: "revoked_at", Value: nil},
	}
	update := bson.D{{Key: "$set", Value: bson.D{{Key: "revoked_at", Value: at}}}}
	result, err := r.col.UpdateOne(ctx, filter, update)
	if err != nil {
		return err
	}
	if result.MatchedCount == 0 {
		return coreerror.ErrNotFound
	}
	return nil
}
