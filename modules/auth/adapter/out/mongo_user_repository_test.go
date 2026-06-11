package adapter

import (
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/bson"
)

func TestBuildUserUpdate(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name      string
		doc       *userDoc
		wantUnset []string
	}{
		{
			name: "all pointer fields nil — all unset (consumed reset token cleared)",
			doc:  &userDoc{ID: "user-1"},
			wantUnset: []string{
				"password_reset_token_hash",
				"password_reset_expires_at",
				"sessions_invalidated_at",
				"locked_until",
			},
		},
		{
			name: "all pointer fields set — nothing unset",
			doc: &userDoc{
				ID:                     "user-1",
				PasswordResetTokenHash: new("hash-abc"),
				PasswordResetExpiresAt: new(now),
				SessionsInvalidatedAt:  new(now),
				LockedUntil:            new(now),
			},
			wantUnset: nil,
		},
		{
			name: "reset consumed but sessions invalidated and account locked — only reset fields unset",
			doc: &userDoc{
				ID:                    "user-1",
				SessionsInvalidatedAt: new(now),
				LockedUntil:           new(now),
			},
			wantUnset: []string{
				"password_reset_token_hash",
				"password_reset_expires_at",
			},
		},
		{
			name: "lock expired and cleared — locked_until unset",
			doc: &userDoc{
				ID:                     "user-1",
				PasswordResetTokenHash: new("hash-abc"),
				PasswordResetExpiresAt: new(now),
				SessionsInvalidatedAt:  new(now),
			},
			wantUnset: []string{"locked_until"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			update := buildUserUpdate(tc.doc)

			set := findKey(t, update, "$set")
			if set == nil {
				t.Fatal("update has no $set section")
			}
			if set.(*userDoc) != tc.doc {
				t.Error("$set must carry the full document")
			}

			unsetRaw := findKey(t, update, "$unset")
			if tc.wantUnset == nil {
				if unsetRaw != nil {
					t.Fatalf("expected no $unset section, got %v", unsetRaw)
				}
				return
			}
			unset, ok := unsetRaw.(bson.D)
			if !ok {
				t.Fatalf("expected $unset section, got %T", unsetRaw)
			}
			got := make([]string, 0, len(unset))
			for _, e := range unset {
				got = append(got, e.Key)
			}
			if len(got) != len(tc.wantUnset) {
				t.Fatalf("$unset keys = %v, want %v", got, tc.wantUnset)
			}
			for i, key := range tc.wantUnset {
				if got[i] != key {
					t.Errorf("$unset[%d] = %q, want %q", i, got[i], key)
				}
			}
		})
	}
}

func findKey(t *testing.T, d bson.D, key string) any {
	t.Helper()
	for _, e := range d {
		if e.Key == key {
			return e.Value
		}
	}
	return nil
}
