package adapter

import (
	"context"
	"errors"
	"testing"
	"time"

	coreerror "sc/core/error"
	"sc/core/event"
	"sc/handler/eventbus"
	mongorepo "sc/infrastructure/repository/mongo"
	"sc/modules/auth/domain/entity"
)

// txTestTopic is local to this file: the bus is constructed per subtest, so no
// subscription leaks between them.
const txTestTopic = event.Topic("unit_of_work_tx_probe")

const txTestTokenTTL = 30 * 24 * time.Hour

// TestPublishInsideUnitOfWorkJoinsTransaction proves the one property the event
// bus's design claims but cannot demonstrate by construction: a handler invoked
// by Publish inside uow.Do writes through the caller's Mongo transaction and
// rolls back with it.
//
// It is not ceremony. Publish wraps the context it was given (the depth counter
// in descend), so the value the handler receives is no longer of dynamic type
// mongo.SessionContext. The session survives only because the driver looks the
// session up as a context *value* rather than type-asserting. That is a real
// failure mode, not a hypothetical one, and nothing else in the suite covers it.
//
// The last subtest is the deliberate counter-example: a handler that ignores the
// context it is handed writes outside the transaction and is NOT rolled back.
// It pins the discipline stated in docs/event-bus.md §2 — a handler reached by
// Publish inside Do may do nothing but Mongo writes through the ctx it receives
// — as a demonstrated fact rather than a comment nobody has to obey.
func TestPublishInsideUnitOfWorkJoinsTransaction(t *testing.T) {
	client := requireMongo(t)
	uow := mongorepo.NewUnitOfWork(client)

	newRepo := func(t *testing.T) *MongoRefreshTokenRepository {
		t.Helper()
		if err := client.DB.Collection(refreshTokensCollection).Drop(context.Background()); err != nil {
			t.Fatalf("drop %s: %v", refreshTokensCollection, err)
		}
		// Creating the indexes also creates the collection, which must exist
		// before the transaction opens.
		repo, err := NewMongoRefreshTokenRepository(client)
		if err != nil {
			t.Fatalf("NewMongoRefreshTokenRepository: %v", err)
		}
		return repo
	}

	assertPersisted := func(t *testing.T, repo *MongoRefreshTokenRepository, want *entity.RefreshToken, label string) {
		t.Helper()
		got, err := repo.FindByTokenHash(context.Background(), want.TokenHash)
		if err != nil {
			t.Fatalf("FindByTokenHash(%s): %v", label, err)
		}
		assertRefreshTokenEqual(t, want, got)
	}

	assertAbsent := func(t *testing.T, repo *MongoRefreshTokenRepository, tokenHash, label string) {
		t.Helper()
		_, err := repo.FindByTokenHash(context.Background(), tokenHash)
		if !errors.Is(err, coreerror.ErrNotFound) {
			t.Errorf("FindByTokenHash(%s): got %v, want ErrNotFound — the write was not rolled back", label, err)
		}
	}

	// Liveness control, not proof of the transaction claim: a write made outside
	// the transaction would persist here too, once the outer unit commits. What
	// discriminates is the pair below it — the same handler write is absent
	// after a rollback, and present when the handler discards the ctx.
	t.Run("commit: the handler's write persists with the publisher's", func(t *testing.T) {
		repo := newRepo(t)

		business := newTestRefreshToken("rt-tx-commit-business", "user-1", "hash-tx-commit-business", txTestTokenTTL)
		byHandler := newTestRefreshToken("rt-tx-commit-handler", "user-1", "hash-tx-commit-handler", txTestTokenTTL)

		bus := eventbus.New()
		bus.Subscribe(txTestTopic, "save-in-transaction", func(ctx context.Context, _ event.Event) error {
			return repo.Save(ctx, byHandler)
		})

		_, err := uow.Do(context.Background(), func(txCtx context.Context) (any, error) {
			if err := repo.Save(txCtx, business); err != nil {
				return nil, err
			}
			return nil, bus.Publish(txCtx, event.Event{Topic: txTestTopic})
		})
		if err != nil {
			t.Fatalf("uow.Do: %v", err)
		}

		assertPersisted(t, repo, business, "business")
		assertPersisted(t, repo, byHandler, "handler")
	})

	t.Run("rollback: the handler's write rolls back with the publisher's", func(t *testing.T) {
		repo := newRepo(t)

		business := newTestRefreshToken("rt-tx-rollback-business", "user-2", "hash-tx-rollback-business", txTestTokenTTL)
		byHandler := newTestRefreshToken("rt-tx-rollback-handler", "user-2", "hash-tx-rollback-handler", txTestTokenTTL)

		// Absence alone would also be satisfied by a handler that never ran, so
		// the rollback claim needs proof that there was a write to undo.
		handlerRan := false
		bus := eventbus.New()
		bus.Subscribe(txTestTopic, "save-in-transaction", func(ctx context.Context, _ event.Event) error {
			handlerRan = true
			return repo.Save(ctx, byHandler)
		})

		sentinel := errors.New("sentinel rollback error")
		_, err := uow.Do(context.Background(), func(txCtx context.Context) (any, error) {
			if err := repo.Save(txCtx, business); err != nil {
				return nil, err
			}
			if err := bus.Publish(txCtx, event.Event{Topic: txTestTopic}); err != nil {
				return nil, err
			}
			// Abort after the handler has written, so the rollback is what
			// removes its document rather than the handler never running.
			return nil, sentinel
		})
		if !errors.Is(err, sentinel) {
			t.Fatalf("uow.Do returned %v, want sentinel error", err)
		}
		if !handlerRan {
			t.Fatal("handler never ran — the rollback assertions below would pass vacuously")
		}

		assertAbsent(t, repo, business.TokenHash, "business")
		assertAbsent(t, repo, byHandler.TokenHash, "handler")
	})

	t.Run("a failing handler aborts the publisher's transaction", func(t *testing.T) {
		repo := newRepo(t)

		business := newTestRefreshToken("rt-tx-handler-err", "user-3", "hash-tx-handler-err", txTestTokenTTL)

		handlerErr := errors.New("handler refused the event")
		bus := eventbus.New()
		bus.Subscribe(txTestTopic, "always-fails", func(context.Context, event.Event) error {
			return handlerErr
		})

		_, err := uow.Do(context.Background(), func(txCtx context.Context) (any, error) {
			if err := repo.Save(txCtx, business); err != nil {
				return nil, err
			}
			return nil, bus.Publish(txCtx, event.Event{Topic: txTestTopic})
		})
		// Publish labels each handler error and joins them; both wrappers keep
		// the cause reachable, so the caller can branch on its own sentinel.
		if !errors.Is(err, handlerErr) {
			t.Fatalf("uow.Do returned %v, want the handler's error", err)
		}

		assertAbsent(t, repo, business.TokenHash, "business")
	})

	t.Run("a handler ignoring the transaction ctx is not rolled back", func(t *testing.T) {
		repo := newRepo(t)

		business := newTestRefreshToken("rt-tx-detached-business", "user-4", "hash-tx-detached-business", txTestTokenTTL)
		byHandler := newTestRefreshToken("rt-tx-detached-handler", "user-4", "hash-tx-detached-handler", txTestTokenTTL)

		bus := eventbus.New()
		bus.Subscribe(txTestTopic, "writes-outside-the-transaction", func(context.Context, event.Event) error {
			// Deliberately discards the transaction context. This is the
			// mistake the type system cannot catch: it compiles, it runs, and
			// the write silently escapes the unit of work.
			return repo.Save(context.Background(), byHandler)
		})

		sentinel := errors.New("sentinel rollback error")
		_, err := uow.Do(context.Background(), func(txCtx context.Context) (any, error) {
			if err := repo.Save(txCtx, business); err != nil {
				return nil, err
			}
			if err := bus.Publish(txCtx, event.Event{Topic: txTestTopic}); err != nil {
				return nil, err
			}
			return nil, sentinel
		})
		if !errors.Is(err, sentinel) {
			t.Fatalf("uow.Do returned %v, want sentinel error", err)
		}

		assertAbsent(t, repo, business.TokenHash, "business")
		assertPersisted(t, repo, byHandler, "handler")
	})
}
