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

var _ port.UserRepository = (*MongoUserRepository)(nil)

const usersCollection = "users"

type MongoUserRepository struct {
	col *mongo.Collection
}

func NewMongoUserRepository(client *mongorepo.MongoClient) (*MongoUserRepository, error) {
	col := client.DB.Collection(usersCollection)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_, err := col.Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys:    bson.D{{Key: "email", Value: 1}},
		Options: options.Index().SetUnique(true),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create user indexes: %w", err)
	}

	return &MongoUserRepository{col: col}, nil
}

func (r *MongoUserRepository) CreateUser(ctx context.Context, user *entity.User) error {
	_, err := r.col.InsertOne(ctx, toDoc(user))
	if mongo.IsDuplicateKeyError(err) {
		return coreerror.ErrConflict
	}
	return err
}

func (r *MongoUserRepository) FindByEmail(ctx context.Context, email string) (*entity.User, error) {
	return r.findOne(ctx, bson.D{{Key: "email", Value: email}})
}

func (r *MongoUserRepository) FindByID(ctx context.Context, id entity.UserID) (*entity.User, error) {
	return r.findOne(ctx, bson.D{{Key: "_id", Value: string(id)}})
}

func (r *MongoUserRepository) FindByPasswordResetTokenHash(ctx context.Context, tokenHash string) (*entity.User, error) {
	return r.findOne(ctx, bson.D{{Key: "password_reset_token_hash", Value: tokenHash}})
}

func (r *MongoUserRepository) findOne(ctx context.Context, filter bson.D) (*entity.User, error) {
	var doc userDoc
	err := r.col.FindOne(ctx, filter).Decode(&doc)
	if err == mongo.ErrNoDocuments {
		return nil, coreerror.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return toEntity(&doc)
}

func (r *MongoUserRepository) Save(ctx context.Context, user *entity.User) error {
	doc := toDoc(user)
	filter := bson.D{{Key: "_id", Value: doc.ID}}
	update := bson.D{{Key: "$set", Value: doc}}
	opts := options.Update().SetUpsert(true)
	_, err := r.col.UpdateOne(ctx, filter, update, opts)
	return err
}

func (r *MongoUserRepository) UpdateByPasswordResetTokenHash(ctx context.Context, tokenHash string, update func(*entity.User) error) error {
	user, err := r.findOne(ctx, bson.D{{Key: "password_reset_token_hash", Value: tokenHash}})
	if err != nil {
		return err
	}
	if err := update(user); err != nil {
		return err
	}
	// Include token hash in filter so a concurrent consumer gets MatchedCount=0.
	filter := bson.D{
		{Key: "_id", Value: string(user.ID)},
		{Key: "password_reset_token_hash", Value: tokenHash},
	}
	result, err := r.col.UpdateOne(ctx, filter, bson.D{{Key: "$set", Value: toDoc(user)}})
	if err != nil {
		return err
	}
	if result.MatchedCount == 0 {
		return coreerror.ErrNotFound
	}
	return nil
}
