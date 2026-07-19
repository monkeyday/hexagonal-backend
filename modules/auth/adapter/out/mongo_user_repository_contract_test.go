package adapter

import (
	"context"
	"errors"
	"testing"

	coreerror "sc/core/error"
	"sc/modules/auth/domain/entity"
	"sc/modules/auth/port"
)

// TestMongoUserRepository runs the shared user-repository contract against a
// real Mongo, proving parity with the file implementation. Skipped when no
// Mongo is configured. Each subtest starts from an empty collection.
func TestMongoUserRepository(t *testing.T) {
	client := requireMongo(t)
	cipher := testCipher(t)

	runUserRepositoryContract(t, func(t *testing.T) port.UserRepository {
		if err := client.DB.Collection(usersCollection).Drop(context.Background()); err != nil {
			t.Fatalf("drop %s collection: %v", usersCollection, err)
		}
		repo, err := NewMongoUserRepository(client, cipher)
		if err != nil {
			t.Fatalf("NewMongoUserRepository: %v", err)
		}
		return repo
	})
}

// TestMongoUserRepositoryTenantIsolation covers the multi-tenant behaviour the
// file backend intentionally lacks: the unique key is (tenant_id,
// email_blind_index), so the same email may exist in different tenants and
// FindByEmail is scoped to its tenant. This is the WS4 blind-index guarantee.
func TestMongoUserRepositoryTenantIsolation(t *testing.T) {
	client := requireMongo(t)
	if err := client.DB.Collection(usersCollection).Drop(context.Background()); err != nil {
		t.Fatalf("drop %s collection: %v", usersCollection, err)
	}
	repo, err := NewMongoUserRepository(client, testCipher(t))
	if err != nil {
		t.Fatalf("NewMongoUserRepository: %v", err)
	}
	ctx := context.Background()

	const sharedEmail = "shared@example.com"
	acme := newUserForTest("acme-user", sharedEmail)
	acme.TenantID = entity.TenantID("acme")
	globex := newUserForTest("globex-user", sharedEmail)
	globex.TenantID = entity.TenantID("globex")

	for _, u := range []*entity.User{acme, globex} {
		if err := repo.CreateUser(ctx, u); err != nil {
			t.Fatalf("CreateUser(%s): %v", u.TenantID, err)
		}
	}

	t.Run("FindByEmail is scoped to its tenant", func(t *testing.T) {
		for _, tc := range []struct {
			tenant entity.TenantID
			wantID entity.UserID
		}{
			{"acme", acme.ID},
			{"globex", globex.ID},
		} {
			found, err := repo.FindByEmail(ctx, tc.tenant, sharedEmail)
			if err != nil {
				t.Fatalf("FindByEmail(%s): %v", tc.tenant, err)
			}
			if found.ID != tc.wantID {
				t.Errorf("tenant %s: got ID %q, want %q", tc.tenant, found.ID, tc.wantID)
			}
		}
	})

	t.Run("FindByEmail in a tenant without the email returns ErrNotFound", func(t *testing.T) {
		if _, err := repo.FindByEmail(ctx, entity.TenantID("initech"), sharedEmail); !errors.Is(err, coreerror.ErrNotFound) {
			t.Errorf("expected ErrNotFound, got %v", err)
		}
	})

	t.Run("same email is a conflict within one tenant", func(t *testing.T) {
		dup := newUserForTest("acme-dup", sharedEmail)
		dup.TenantID = entity.TenantID("acme")
		if err := repo.CreateUser(ctx, dup); !errors.Is(err, coreerror.ErrConflict) {
			t.Errorf("expected ErrConflict, got %v", err)
		}
	})
}
