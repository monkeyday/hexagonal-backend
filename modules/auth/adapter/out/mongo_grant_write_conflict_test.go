package adapter

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	coreerror "sc/core/error"
	mongorepo "sc/infrastructure/repository/mongo"
	"sc/modules/auth/domain/entity"
)

// barrierTimeout bounds each side of the hand-off below, so a transaction that
// never conflicts fails the test instead of hanging it.
const barrierTimeout = 10 * time.Second

var (
	// errTestGrantRevoked stands in for autherrors.NewErrInvalidRefreshToken:
	// the rejection checkAndExtendGrant returns for a revoked grant.
	errTestGrantRevoked = errors.New("grant revoked")
	// errTestBarrierTimeout marks the hand-off giving up.
	errTestBarrierTimeout = errors.New("barrier timed out")
)

// wrapLikeUseCase reproduces how the rotation use case wraps every repository
// failure before it reaches WithTransaction: autherrors.NewErrGenRefreshTokenFailed
// is coreerror.NewErr(code, err) (errors/error_codes.go:112-114), so the wrapper
// this test must exercise is *coreerror.ErrorStruct and its Unwrap.
//
// This matters more than it looks. §10's retry argument needs the driver's
// TransientTransactionError label to survive the wrapper — mongo-driver's
// errorHasLabel walks the unwrap chain, so it does, but only because
// ErrorStruct implements Unwrap (core/error/error.go:51). Returning the raw
// Save error here would bypass the wrapper and prove a retry the production
// path does not perform.
//
// Constructed from coreerror rather than by importing modules/auth/errors on
// purpose: the adapter package imports no application-layer package, and the
// error code is irrelevant to the label walk. Do not "fix" this by importing
// autherrors.
func wrapLikeUseCase(err error) error {
	if err == nil {
		return nil
	}
	return coreerror.NewErr(coreerror.Internal, err)
}

// TestMongoGrantWriteConflict is the empirical test for grant-linkage.md §10's
// central claim: because rotation *writes* the grant document (ExtendToCover)
// inside the transaction, a Revoke that commits after the transaction's read
// raises a write conflict, WithTransaction retries, and the retry sees the
// revocation and rejects. That is what makes the grant document a serialization
// point which a multi-row sweep cannot be — the property that closes the
// revocation escape. Until this ran it was reasoning only.
//
// Only the Mongo backend can carry it: the file backend runs NoopUnitOfWork, so
// there is no snapshot and no conflict to raise.
func TestMongoGrantWriteConflict(t *testing.T) {
	client := requireMongo(t)
	uow := mongorepo.NewUnitOfWork(client)

	newRepo := func(t *testing.T) *MongoGrantRepository {
		t.Helper()
		if err := client.DB.Collection(grantsCollection).Drop(context.Background()); err != nil {
			t.Fatalf("drop %s collection: %v", grantsCollection, err)
		}
		repo, err := NewMongoGrantRepository(client)
		if err != nil {
			t.Fatalf("NewMongoGrantRepository: %v", err)
		}
		return repo
	}

	// rotate mirrors the order of RefreshTokenUseCase.checkAndExtendGrant: find,
	// reject when invalid, extend, save — all inside the transaction, with every
	// repository error wrapped the way the use case wraps it. It deliberately
	// omits that function's ErrNotFound fail-open branch, which no subtest here
	// reaches because both seed their grant.
	//
	// pause runs after the read and before the write, and only for the first
	// attempt that reaches it. That window is the only one in which an outside
	// Revoke can commit without blocking on this transaction's own uncommitted
	// write.
	rotate := func(
		repo *MongoGrantRepository,
		grantID entity.GrantID,
		tokenExpiry time.Time,
		attempts *atomic.Int32,
		pause func() error,
	) error {
		var pauseOnce sync.Once
		_, err := uow.Do(context.Background(), func(txCtx context.Context) (any, error) {
			attempts.Add(1)
			grant, err := repo.FindByID(txCtx, grantID)
			if err != nil {
				return nil, wrapLikeUseCase(err)
			}
			if pause != nil {
				var pauseErr error
				pauseOnce.Do(func() { pauseErr = pause() })
				if pauseErr != nil {
					return nil, pauseErr
				}
			}
			if !grant.IsValid() {
				// Wrapped like the use case's rejection, which is an ErrorStruct
				// too. Subtest 2's attempts == 1 is what proves the wrapper does
				// not make a non-transient rejection look retryable.
				return nil, wrapLikeUseCase(errTestGrantRevoked)
			}
			grant.ExtendToCover(tokenExpiry)
			return nil, wrapLikeUseCase(repo.Save(txCtx, grant))
		})
		return err
	}

	t.Run("revoke committed mid-transaction: rotation retries and rejects", func(t *testing.T) {
		repo := newRepo(t)
		ctx := context.Background()

		g := newTestGrant("user-conflict", "client-1")
		if err := repo.Save(ctx, g); err != nil {
			t.Fatalf("seed grant: %v", err)
		}
		originalExpiry := g.ExpiresAt
		tokenExpiry := time.Now().Add(entity.RefreshTokenTTL)

		readDone := make(chan struct{})   // first attempt has read the grant
		revokeDone := make(chan struct{}) // the outside Revoke has committed
		var revokeErr error

		go func() {
			defer close(revokeDone)
			select {
			case <-readDone:
			case <-time.After(barrierTimeout):
				revokeErr = errTestBarrierTimeout
				return
			}
			revokeErr = repo.Revoke(context.Background(), g.ID, time.Now())
		}()

		var attempts atomic.Int32
		err := rotate(repo, g.ID, tokenExpiry, &attempts, func() error {
			close(readDone)
			select {
			case <-revokeDone:
				return nil
			case <-time.After(barrierTimeout):
				return errTestBarrierTimeout
			}
		})

		<-revokeDone
		if revokeErr != nil {
			t.Fatalf("concurrent Revoke: %v", revokeErr)
		}
		if !errors.Is(err, errTestGrantRevoked) {
			t.Fatalf("rotation returned %v, want the revoked-grant rejection", err)
		}
		// The rejection must come from a *retry*. One attempt would mean the
		// write never conflicted and the rejection came from somewhere else,
		// which would leave §10's serialization-point argument unproven.
		if got := attempts.Load(); got < 2 {
			t.Errorf("closure ran %d time(s), want >= 2 — the write did not conflict", got)
		}

		found, err := repo.FindByID(ctx, g.ID)
		if err != nil {
			t.Fatalf("FindByID after rotation: %v", err)
		}
		if found.RevokedAt == nil {
			t.Error("grant must stay revoked; the rotation overwrote the revocation")
		}
		if !found.ExpiresAt.Equal(originalExpiry) {
			t.Errorf("ExpiresAt: got %v, want %v — the rejected rotation still extended the grant",
				found.ExpiresAt, originalExpiry)
		}
	})

	t.Run("revoke committed before the transaction: rejected without a retry", func(t *testing.T) {
		repo := newRepo(t)
		ctx := context.Background()

		g := newTestGrant("user-preRevoked", "client-1")
		if err := repo.Save(ctx, g); err != nil {
			t.Fatalf("seed grant: %v", err)
		}
		if err := repo.Revoke(ctx, g.ID, time.Now()); err != nil {
			t.Fatalf("Revoke: %v", err)
		}

		var attempts atomic.Int32
		err := rotate(repo, g.ID, time.Now().Add(entity.RefreshTokenTTL), &attempts, nil)

		if !errors.Is(err, errTestGrantRevoked) {
			t.Fatalf("rotation returned %v, want the revoked-grant rejection", err)
		}
		// The control for the subtest above: this rejection needs no conflict,
		// so a single attempt is what it takes. It pins the >= 2 there to the
		// retry, not to something inherent in the closure.
		if got := attempts.Load(); got != 1 {
			t.Errorf("closure ran %d time(s), want exactly 1", got)
		}
	})
}
