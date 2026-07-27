package entity

import (
	"testing"
	"time"
)

func TestNewGrant(t *testing.T) {
	tests := []struct {
		name     string
		userID   UserID
		clientID ClientID
	}{
		{
			name:     "with client",
			userID:   UserID("user-1"),
			clientID: ClientID("client-1"),
		},
		{
			name:     "password grant — empty clientID",
			userID:   UserID("user-2"),
			clientID: ClientID(""),
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			before := time.Now()
			g := NewGrant(tc.userID, tc.clientID)
			after := time.Now()

			if g.ID == "" {
				t.Error("ID must not be empty")
			}
			if g.UserID != tc.userID {
				t.Errorf("UserID = %q, want %q", g.UserID, tc.userID)
			}
			if g.ClientID != tc.clientID {
				t.Errorf("ClientID = %q, want %q", g.ClientID, tc.clientID)
			}
			if g.RevokedAt != nil {
				t.Error("RevokedAt must be nil on a fresh grant")
			}
			wantExpiry := g.CreatedAt.Add(RefreshTokenTTL)
			if !g.ExpiresAt.Equal(wantExpiry) {
				t.Errorf("ExpiresAt = %v, want CreatedAt+RefreshTokenTTL = %v", g.ExpiresAt, wantExpiry)
			}
			if g.CreatedAt.Before(before) || g.CreatedAt.After(after) {
				t.Errorf("CreatedAt = %v, want between %v and %v", g.CreatedAt, before, after)
			}
			if !g.AuthenticatedAt.Equal(g.CreatedAt) {
				t.Errorf("AuthenticatedAt = %v, want equal to CreatedAt %v", g.AuthenticatedAt, g.CreatedAt)
			}
		})
	}
}

func TestGrantIsValid(t *testing.T) {
	now := time.Now()

	t.Run("fresh grant — true", func(t *testing.T) {
		g := NewGrant(UserID("u"), ClientID("c"))
		if !g.IsValid() {
			t.Error("fresh grant should be valid")
		}
	})

	t.Run("revoked — false", func(t *testing.T) {
		g := NewGrant(UserID("u"), ClientID("c"))
		g.RevokedAt = &now
		if g.IsValid() {
			t.Error("revoked grant should not be valid")
		}
	})

	t.Run("expired — false", func(t *testing.T) {
		g := NewGrant(UserID("u"), ClientID("c"))
		g.ExpiresAt = time.Now().Add(-time.Minute)
		if g.IsValid() {
			t.Error("expired grant should not be valid")
		}
	})
}
