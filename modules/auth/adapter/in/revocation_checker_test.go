package adapter

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	corejwt "sc/core/jwt"
	"sc/modules/auth/application/define"
	"sc/modules/auth/domain/entity"
)

// fakeReadCache is a hand-written fake for corecache.ReadErrorCache.
// It returns the pre-configured (hit, err) pair for each key and records
// every key consulted, allowing assertions on short-circuit behaviour.
// When hit is true and value is non-nil, value is JSON-marshaled into dest.
type fakeReadCache struct {
	responses map[string]fakeResponse
	consulted []string
}

type fakeResponse struct {
	hit   bool
	value any // JSON-marshaled into dest when hit && dest != nil
	err   error
}

func (f *fakeReadCache) GetErr(_ context.Context, key string, dest any) (bool, error) {
	f.consulted = append(f.consulted, key)
	if r, ok := f.responses[key]; ok {
		if r.hit && dest != nil && r.value != nil {
			b, _ := json.Marshal(r.value)
			_ = json.Unmarshal(b, dest)
		}
		return r.hit, r.err
	}
	return false, nil
}

func (f *fakeReadCache) wasConsulted(key string) bool {
	for _, k := range f.consulted {
		if k == key {
			return true
		}
	}
	return false
}

func TestRevocationChecker_IsRevoked(t *testing.T) {
	ctx := context.Background()

	const (
		jti     = "tok-123"
		grantID = "grant-abc"
		userID  = "user-sub"
	)

	blacklistKey := define.BlacklistKey(jti)
	grantKey := define.RevokedGrantKey(grantID)
	markerKey := define.SessionsInvalidatedKey(entity.UserID(userID))

	errCache := errors.New("cache unavailable")

	// iat fixed in the past; marker timestamps are defined relative to it.
	iat := time.Unix(1_000_000, 0)
	beforeIAT := iat.Unix() - 1 // marker older than token → token admitted
	atIAT := iat.Unix()         // marker same second as token → token rejected (inclusive)
	afterIAT := iat.Unix() + 1  // marker newer than token → token rejected

	tests := []struct {
		name            string
		responses       map[string]fakeResponse
		claims          *corejwt.Claims
		wantRevoked     bool
		wantErr         bool
		grantConsulted  bool
		markerConsulted *bool // nil = don't assert
	}{
		// ── original six tests, adapted to *corejwt.Claims ───────────────────
		{
			name: "clean jti, clean grant — not revoked",
			responses: map[string]fakeResponse{
				blacklistKey: {hit: false},
				grantKey:     {hit: false},
			},
			claims:          &corejwt.Claims{ID: jti, GrantID: grantID, Subject: userID, IssuedAt: new(iat)},
			wantRevoked:     false,
			grantConsulted:  true,
			markerConsulted: new(true),
		},
		{
			name: "blacklisted jti — revoked, grant key not consulted",
			responses: map[string]fakeResponse{
				blacklistKey: {hit: true},
			},
			claims:          &corejwt.Claims{ID: jti, GrantID: grantID, Subject: userID, IssuedAt: new(iat)},
			wantRevoked:     true,
			grantConsulted:  false,
			markerConsulted: new(false),
		},
		{
			name: "clean jti, revoked grant — revoked",
			responses: map[string]fakeResponse{
				blacklistKey: {hit: false},
				grantKey:     {hit: true},
			},
			claims:          &corejwt.Claims{ID: jti, GrantID: grantID, Subject: userID, IssuedAt: new(iat)},
			wantRevoked:     true,
			grantConsulted:  true,
			markerConsulted: new(false),
		},
		{
			name: "empty grantID with clean jti — not revoked, grant key not consulted",
			responses: map[string]fakeResponse{
				blacklistKey: {hit: false},
			},
			claims:          &corejwt.Claims{ID: jti, Subject: userID, IssuedAt: new(iat)},
			wantRevoked:     false,
			grantConsulted:  false,
			markerConsulted: new(true),
		},
		{
			name: "blacklist lookup error — fail-closed",
			responses: map[string]fakeResponse{
				blacklistKey: {err: errCache},
			},
			claims:          &corejwt.Claims{ID: jti, GrantID: grantID, Subject: userID, IssuedAt: new(iat)},
			wantRevoked:     false,
			wantErr:         true,
			grantConsulted:  false,
			markerConsulted: new(false),
		},
		{
			name: "grant lookup error — fail-closed",
			responses: map[string]fakeResponse{
				blacklistKey: {hit: false},
				grantKey:     {err: errCache},
			},
			claims:          &corejwt.Claims{ID: jti, GrantID: grantID, Subject: userID, IssuedAt: new(iat)},
			wantRevoked:     false,
			wantErr:         true,
			grantConsulted:  true,
			markerConsulted: new(false),
		},
		// ── third layer: sessions_invalidated marker ──────────────────────────
		{
			name: "clean jti, clean grant, no invalidation marker — not revoked",
			responses: map[string]fakeResponse{
				blacklistKey: {hit: false},
				grantKey:     {hit: false},
				// markerKey not seeded → (false, nil) by default
			},
			claims:          &corejwt.Claims{ID: jti, GrantID: grantID, Subject: userID, IssuedAt: new(iat)},
			wantRevoked:     false,
			grantConsulted:  true,
			markerConsulted: new(true),
		},
		{
			name: "iat before invalidation marker — revoked",
			responses: map[string]fakeResponse{
				blacklistKey: {hit: false},
				markerKey:    {hit: true, value: afterIAT},
			},
			claims:          &corejwt.Claims{ID: jti, Subject: userID, IssuedAt: new(iat)},
			wantRevoked:     true,
			grantConsulted:  false,
			markerConsulted: new(true),
		},
		{
			name: "iat after invalidation marker — not revoked",
			responses: map[string]fakeResponse{
				blacklistKey: {hit: false},
				markerKey:    {hit: true, value: beforeIAT},
			},
			claims:          &corejwt.Claims{ID: jti, Subject: userID, IssuedAt: new(iat)},
			wantRevoked:     false,
			grantConsulted:  false,
			markerConsulted: new(true),
		},
		{
			name: "iat equal to invalidation marker — revoked (inclusive)",
			responses: map[string]fakeResponse{
				blacklistKey: {hit: false},
				markerKey:    {hit: true, value: atIAT},
			},
			claims:          &corejwt.Claims{ID: jti, Subject: userID, IssuedAt: new(iat)},
			wantRevoked:     true,
			grantConsulted:  false,
			markerConsulted: new(true),
		},
		{
			name: "marker lookup error — fail-closed",
			responses: map[string]fakeResponse{
				blacklistKey: {hit: false},
				markerKey:    {err: errCache},
			},
			claims:          &corejwt.Claims{ID: jti, Subject: userID, IssuedAt: new(iat)},
			wantRevoked:     false,
			wantErr:         true,
			grantConsulted:  false,
			markerConsulted: new(true),
		},
		{
			name: "IssuedAt nil — user-level layer skipped, marker not consulted",
			responses: map[string]fakeResponse{
				blacklistKey: {hit: false},
			},
			claims:          &corejwt.Claims{ID: jti, Subject: userID},
			wantRevoked:     false,
			grantConsulted:  false,
			markerConsulted: new(false),
		},
		{
			name: "blacklisted jti short-circuits before marker key is read",
			responses: map[string]fakeResponse{
				blacklistKey: {hit: true},
				markerKey:    {hit: true, value: afterIAT},
			},
			claims:          &corejwt.Claims{ID: jti, Subject: userID, IssuedAt: new(iat)},
			wantRevoked:     true,
			grantConsulted:  false,
			markerConsulted: new(false),
		},
		{
			name: "revoked grant short-circuits before marker key is read",
			responses: map[string]fakeResponse{
				blacklistKey: {hit: false},
				grantKey:     {hit: true},
				markerKey:    {hit: true, value: afterIAT},
			},
			claims:          &corejwt.Claims{ID: jti, GrantID: grantID, Subject: userID, IssuedAt: new(iat)},
			wantRevoked:     true,
			grantConsulted:  true,
			markerConsulted: new(false),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fake := &fakeReadCache{responses: tc.responses}
			checker := newRevocationChecker(fake)

			revoked, err := checker.IsRevoked(ctx, tc.claims)

			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
			}

			if revoked != tc.wantRevoked {
				t.Errorf("revoked = %v, want %v", revoked, tc.wantRevoked)
			}

			wasGrantConsulted := fake.wasConsulted(grantKey)
			if wasGrantConsulted != tc.grantConsulted {
				if tc.grantConsulted {
					t.Error("expected grant key to be consulted, but it was not")
				} else {
					t.Error("expected grant key NOT to be consulted, but it was")
				}
			}

			if tc.markerConsulted != nil {
				wasMarkerConsulted := fake.wasConsulted(markerKey)
				if wasMarkerConsulted != *tc.markerConsulted {
					if *tc.markerConsulted {
						t.Error("expected sessions_invalidated key to be consulted, but it was not")
					} else {
						t.Error("expected sessions_invalidated key NOT to be consulted, but it was")
					}
				}
			}
		})
	}
}
