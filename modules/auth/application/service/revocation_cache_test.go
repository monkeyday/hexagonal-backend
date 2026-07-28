package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"sc/modules/auth/application/define"
	"sc/modules/auth/domain/entity"
)

// spyCache records the single Set the revocation writers are expected to make.
type spyCache struct {
	key    string
	value  any
	ttl    *time.Duration
	setErr error
	sets   int
}

func (c *spyCache) Set(_ context.Context, key string, value any, ttl *time.Duration) error {
	c.sets++
	c.key, c.value, c.ttl = key, value, ttl
	return c.setErr
}

func (c *spyCache) GetErr(_ context.Context, _ string, _ any) (bool, error) { return false, nil }
func (c *spyCache) Get(_ context.Context, _ string, _ any) bool             { return false }
func (c *spyCache) GetAndDelete(_ context.Context, _ string, _ any) bool    { return false }
func (c *spyCache) Delete(_ context.Context, _ string)                      {}
func (c *spyCache) IncrWindow(_ context.Context, _ string, _ time.Duration) (int64, error) {
	return 0, nil
}

// The expected keys are spelled out as literals on purpose: this test pins the
// stored wire format, so deriving them from define would make it tautological.
func TestRevocationCache_MarkerKeyAndTTL(t *testing.T) {
	ctx := context.Background()
	expiresAt := time.Now().Add(30 * time.Minute)

	tests := []struct {
		name      string
		write     func(*RevocationCache) error
		wantKey   string
		wantTTL   time.Duration
		tolerance time.Duration
	}{
		{
			name:      "blacklisted JTI expires with the token itself",
			write:     func(rc *RevocationCache) error { return rc.BlacklistJTI(ctx, "jti-123", expiresAt) },
			wantKey:   "blacklist:jti-123",
			wantTTL:   time.Until(expiresAt),
			tolerance: time.Second, // TTL is computed from time.Now inside the call
		},
		{
			name:    "grant marker outlives any access token issued under the grant",
			write:   func(rc *RevocationCache) error { return rc.MarkGrantRevoked(ctx, entity.GrantID("grant-abc")) },
			wantKey: "revoked_grant:grant-abc",
			wantTTL: define.RevokedGrantMarkerTTL,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cache := &spyCache{}
			if err := tt.write(NewRevocationCache(cache)); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if cache.sets != 1 {
				t.Fatalf("cache Set called %d times, want 1", cache.sets)
			}
			if cache.key != tt.wantKey {
				t.Errorf("cache key = %q, want %q", cache.key, tt.wantKey)
			}
			if cache.value != true {
				t.Errorf("cache value = %v, want true", cache.value)
			}
			if cache.ttl == nil {
				t.Fatal("marker written without a TTL — it would never expire")
			}
			if diff := (*cache.ttl - tt.wantTTL).Abs(); diff > tt.tolerance {
				t.Errorf("TTL = %v, want %v (tolerance %v)", *cache.ttl, tt.wantTTL, tt.tolerance)
			}
		})
	}
}

func TestRevocationCache_PropagatesCacheError(t *testing.T) {
	ctx := context.Background()
	setErr := errors.New("cache unavailable")

	tests := []struct {
		name  string
		write func(*RevocationCache) error
	}{
		{
			name:  "BlacklistJTI",
			write: func(rc *RevocationCache) error { return rc.BlacklistJTI(ctx, "jti-123", time.Now().Add(time.Hour)) },
		},
		{
			name:  "MarkGrantRevoked",
			write: func(rc *RevocationCache) error { return rc.MarkGrantRevoked(ctx, "grant-abc") },
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.write(NewRevocationCache(&spyCache{setErr: setErr})); !errors.Is(err, setErr) {
				t.Errorf("error = %v, want %v — callers decide the policy, so the error must reach them", err, setErr)
			}
		})
	}
}

// Callers that treat marker writes as best-effort nil-check the collaborator.
func TestNewRevocationCache_NilCache(t *testing.T) {
	if rc := NewRevocationCache(nil); rc != nil {
		t.Errorf("NewRevocationCache(nil) = %v, want nil", rc)
	}
}
