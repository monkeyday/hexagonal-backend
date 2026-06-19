package adapter

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	mongorepo "sc/infrastructure/repository/mongo"
)

// requireMongo connects to a Mongo instance for integration/parity tests, or
// skips when none is configured. It uses a throwaway, uniquely-named database
// that is dropped on cleanup, so it never touches real data and parallel runs
// don't collide. Honors MONGO_TEST_* overrides, falling back to the same
// MONGO_* vars the server reads.
func requireMongo(t *testing.T) *mongorepo.MongoClient {
	t.Helper()

	host := firstNonEmpty(os.Getenv("MONGO_TEST_HOST"), os.Getenv("MONGO_HOST"))
	if host == "" {
		t.Skip("set MONGO_HOST (or MONGO_TEST_HOST) to run Mongo parity tests")
	}

	cfg := mongorepo.Config{
		Host:       host,
		Username:   firstNonEmpty(os.Getenv("MONGO_TEST_USER"), os.Getenv("MONGO_USER")),
		Password:   firstNonEmpty(os.Getenv("MONGO_TEST_PASSWORD"), os.Getenv("MONGO_PASSWORD")),
		AuthSource: firstNonEmpty(os.Getenv("MONGO_TEST_AUTH_SOURCE"), os.Getenv("MONGO_AUTH_SOURCE")),
		Database:   fmt.Sprintf("parity_test_%d", time.Now().UnixNano()),
		Direct:     true,
	}

	client, err := mongorepo.NewMongoClient(cfg)
	if err != nil {
		t.Fatalf("connect mongo at %s: %v", host, err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = client.DB.Drop(ctx)
		_ = client.Disconnect(ctx)
	})
	return client
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
