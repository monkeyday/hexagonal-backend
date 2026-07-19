package adapter

import (
	"context"
	"fmt"
	"time"

	"sc/core/crypto"
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
	col   *mongo.Collection
	codec *userCodec
}

func NewMongoUserRepository(client *mongorepo.MongoClient, c *crypto.Cipher) (*MongoUserRepository, error) {
	col := client.DB.Collection(usersCollection)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_, err := col.Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys: bson.D{
			{Key: "tenant_id", Value: 1},
			{Key: "email_blind_index", Value: 1},
		},
		Options: options.Index().SetUnique(true),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create user indexes: %w", err)
	}

	return &MongoUserRepository{col: col, codec: newUserCodec(c)}, nil
}

func (r *MongoUserRepository) CreateUser(ctx context.Context, user *entity.User) error {
	_, err := r.col.InsertOne(ctx, r.codec.toDoc(user))
	if mongo.IsDuplicateKeyError(err) {
		return coreerror.ErrConflict
	}
	return err
}

func (r *MongoUserRepository) FindByEmail(ctx context.Context, tenantID entity.TenantID, email string) (*entity.User, error) {
	bi := r.codec.cipher.BlindIndex(email)
	return r.findOne(ctx, bson.D{
		{Key: "tenant_id", Value: string(tenantID)},
		{Key: "email_blind_index", Value: bi},
	})
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
	return r.codec.toEntity(&doc)
}

func (r *MongoUserRepository) Save(ctx context.Context, user *entity.User) error {
	doc := r.codec.toDoc(user)
	filter := bson.D{{Key: "_id", Value: doc.ID}}
	opts := options.Update().SetUpsert(true)
	_, err := r.col.UpdateOne(ctx, filter, buildUserUpdate(doc), opts)
	return err
}

// buildUserUpdate returns $set for the document plus $unset for nil pointer
// fields: their bson omitempty tag drops them from $set, which would leave
// stale values (e.g. a consumed password-reset token) in Mongo.
func buildUserUpdate(doc *userDoc) bson.D {
	update := bson.D{{Key: "$set", Value: doc}}
	unset := bson.D{}
	if doc.PasswordResetTokenHash == nil {
		unset = append(unset, bson.E{Key: "password_reset_token_hash", Value: ""})
	}
	if doc.PasswordResetExpiresAt == nil {
		unset = append(unset, bson.E{Key: "password_reset_expires_at", Value: ""})
	}
	if doc.SessionsInvalidatedAt == nil {
		unset = append(unset, bson.E{Key: "sessions_invalidated_at", Value: ""})
	}
	if doc.LockedUntil == nil {
		unset = append(unset, bson.E{Key: "locked_until", Value: ""})
	}
	if len(unset) > 0 {
		update = append(update, bson.E{Key: "$unset", Value: unset})
	}
	return update
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
	result, err := r.col.UpdateOne(ctx, filter, buildUserUpdate(r.codec.toDoc(user)))
	if err != nil {
		return err
	}
	if result.MatchedCount == 0 {
		return coreerror.ErrNotFound
	}
	return nil
}
