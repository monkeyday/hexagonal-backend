package adapter

import (
	"context"
	"testing"

	"sc/modules/auth/port"
)

// TestMongoRefreshTokenRepository runs the shared refresh-token contract against
// a real Mongo, proving parity with the file implementation. Skipped when no
// Mongo is configured (see requireMongo). Each subtest starts from an empty
// collection.
func TestMongoRefreshTokenRepository(t *testing.T) {
	client := requireMongo(t)

	runRefreshTokenContract(t, func(t *testing.T) port.RefreshTokenRepository {
		if err := client.DB.Collection(refreshTokensCollection).Drop(context.Background()); err != nil {
			t.Fatalf("drop %s collection: %v", refreshTokensCollection, err)
		}
		repo, err := NewMongoRefreshTokenRepository(client)
		if err != nil {
			t.Fatalf("NewMongoRefreshTokenRepository: %v", err)
		}
		return repo
	})
}
