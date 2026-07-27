package adapter

import (
	"context"
	"errors"
	"testing"

	"sc/modules/auth/application/define"
)

// fakeReadCache is a hand-written fake for corecache.ReadErrorCache.
// It returns the pre-configured (hit, err) pair for each key and records
// every key consulted, allowing assertions on short-circuit behaviour.
type fakeReadCache struct {
	responses map[string]fakeResponse
	consulted []string
}

type fakeResponse struct {
	hit bool
	err error
}

func (f *fakeReadCache) GetErr(_ context.Context, key string, _ any) (bool, error) {
	f.consulted = append(f.consulted, key)
	if r, ok := f.responses[key]; ok {
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
	)

	blacklistKey := define.BlacklistKey(jti)
	grantKey := define.RevokedGrantKey(grantID)

	errCache := errors.New("cache unavailable")

	tests := []struct {
		name           string
		responses      map[string]fakeResponse
		jti            string
		grantID        string
		wantRevoked    bool
		wantErr        bool
		grantConsulted bool
	}{
		{
			name: "clean jti, clean grant — not revoked",
			responses: map[string]fakeResponse{
				blacklistKey: {false, nil},
				grantKey:     {false, nil},
			},
			jti:            jti,
			grantID:        grantID,
			wantRevoked:    false,
			wantErr:        false,
			grantConsulted: true,
		},
		{
			name: "blacklisted jti — revoked, grant key not consulted",
			responses: map[string]fakeResponse{
				blacklistKey: {true, nil},
			},
			jti:            jti,
			grantID:        grantID,
			wantRevoked:    true,
			wantErr:        false,
			grantConsulted: false,
		},
		{
			name: "clean jti, revoked grant — revoked",
			responses: map[string]fakeResponse{
				blacklistKey: {false, nil},
				grantKey:     {true, nil},
			},
			jti:            jti,
			grantID:        grantID,
			wantRevoked:    true,
			wantErr:        false,
			grantConsulted: true,
		},
		{
			name: "empty grantID with clean jti — not revoked, grant key not consulted",
			responses: map[string]fakeResponse{
				blacklistKey: {false, nil},
			},
			jti:            jti,
			grantID:        "",
			wantRevoked:    false,
			wantErr:        false,
			grantConsulted: false,
		},
		{
			name: "blacklist lookup error — fail-closed",
			responses: map[string]fakeResponse{
				blacklistKey: {false, errCache},
			},
			jti:            jti,
			grantID:        grantID,
			wantRevoked:    false,
			wantErr:        true,
			grantConsulted: false,
		},
		{
			name: "grant lookup error — fail-closed",
			responses: map[string]fakeResponse{
				blacklistKey: {false, nil},
				grantKey:     {false, errCache},
			},
			jti:            jti,
			grantID:        grantID,
			wantRevoked:    false,
			wantErr:        true,
			grantConsulted: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fake := &fakeReadCache{responses: tc.responses}
			checker := newRevocationChecker(fake)

			revoked, err := checker.IsRevoked(ctx, tc.jti, tc.grantID)

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
		})
	}
}
