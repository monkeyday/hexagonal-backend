package adapter

import (
	"context"
	"errors"
	"testing"

	mongorepo "sc/infrastructure/repository/mongo"
)

// TestMongoUnitOfWorkRefreshRotation proves that the UnitOfWork wraps the
// refresh-token rotation in a real MongoDB transaction: a successful closure
// commits both the revocation and the new token, while a closure that returns
// an error rolls both writes back.
func TestMongoUnitOfWorkRefreshRotation(t *testing.T) {
	client := requireMongo(t)
	uow := mongorepo.NewUnitOfWork(client)

	newRepo := func(t *testing.T) *MongoRefreshTokenRepository {
		t.Helper()
		if err := client.DB.Collection(refreshTokensCollection).Drop(context.Background()); err != nil {
			t.Fatalf("drop %s: %v", refreshTokensCollection, err)
		}
		repo, err := NewMongoRefreshTokenRepository(client)
		if err != nil {
			t.Fatalf("NewMongoRefreshTokenRepository: %v", err)
		}
		return repo
	}

	t.Run("commit: revoke A and save B both persist", func(t *testing.T) {
		repo := newRepo(t)
		ctx := context.Background()

		tokenA := newTestRefreshToken("rt-commit-a", "user-1", "hash-commit-a", 30*24*3600e9)
		tokenB := newTestRefreshToken("rt-commit-b", "user-1", "hash-commit-b", 30*24*3600e9)

		if err := repo.Save(ctx, tokenA); err != nil {
			t.Fatalf("seed tokenA: %v", err)
		}

		_, err := uow.Do(ctx, func(ctx context.Context) (any, error) {
			if err := repo.RevokeByTokenHash(ctx, tokenA.TokenHash); err != nil {
				return nil, err
			}
			return nil, repo.Save(ctx, tokenB)
		})
		if err != nil {
			t.Fatalf("uow.Do: %v", err)
		}

		// A must be revoked
		foundA, err := repo.FindByTokenHash(ctx, tokenA.TokenHash)
		if err != nil {
			t.Fatalf("FindByTokenHash(A): %v", err)
		}
		if foundA.RevokedAt == nil {
			t.Error("tokenA should be revoked after commit")
		}

		// B must be findable
		foundB, err := repo.FindByTokenHash(ctx, tokenB.TokenHash)
		if err != nil {
			t.Fatalf("FindByTokenHash(B): %v", err)
		}
		assertRefreshTokenEqual(t, tokenB, foundB)
	})

	t.Run("rollback: revoke C rolled back on sentinel error", func(t *testing.T) {
		repo := newRepo(t)
		ctx := context.Background()

		tokenC := newTestRefreshToken("rt-rollback-c", "user-2", "hash-rollback-c", 30*24*3600e9)

		if err := repo.Save(ctx, tokenC); err != nil {
			t.Fatalf("seed tokenC: %v", err)
		}

		sentinel := errors.New("sentinel rollback error")
		_, err := uow.Do(ctx, func(ctx context.Context) (any, error) {
			if err := repo.RevokeByTokenHash(ctx, tokenC.TokenHash); err != nil {
				return nil, err
			}
			return nil, sentinel
		})
		if !errors.Is(err, sentinel) {
			t.Fatalf("uow.Do returned %v, want sentinel error", err)
		}

		// C must still be un-revoked (transaction rolled back)
		foundC, err := repo.FindByTokenHash(ctx, tokenC.TokenHash)
		if err != nil {
			t.Fatalf("FindByTokenHash(C): %v", err)
		}
		if foundC.RevokedAt != nil {
			t.Error("tokenC must remain un-revoked after rollback")
		}
	})
}
