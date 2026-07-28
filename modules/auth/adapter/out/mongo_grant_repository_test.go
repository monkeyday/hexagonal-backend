package adapter

import (
	"context"
	"testing"

	"sc/modules/auth/port"
)

// TestMongoGrantRepository runs the shared grant contract against a real Mongo,
// proving parity with the file implementation. Skipped when no Mongo is
// configured (see requireMongo). Each subtest starts from an empty collection.
func TestMongoGrantRepository(t *testing.T) {
	client := requireMongo(t)

	runGrantContract(t, func(t *testing.T) port.GrantRepository {
		if err := client.DB.Collection(grantsCollection).Drop(context.Background()); err != nil {
			t.Fatalf("drop %s collection: %v", grantsCollection, err)
		}
		repo, err := NewMongoGrantRepository(client)
		if err != nil {
			t.Fatalf("NewMongoGrantRepository: %v", err)
		}
		return repo
	})
}
