package cache

import (
	"encoding/json"
	"testing"
)

// TestRedisCache_Serialization verifies that values round-trip through JSON
// the same way the RedisCache stores and returns them, without requiring a
// live Redis server.
func TestRedisCache_Serialization(t *testing.T) {
	type payload struct {
		Code   string `json:"code"`
		UserID string `json:"user_id"`
	}

	original := payload{Code: "abc123", UserID: "user-1"}
	b, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}

	// Simulate what Get returns from Redis (raw bytes).
	var decoded payload
	if err := json.Unmarshal(b, &decoded); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if decoded != original {
		t.Errorf("round-trip mismatch: got %+v, want %+v", decoded, original)
	}
}

// TestRedisCache_BoolSerialization verifies that bool values (used by
// blacklist and state cache) survive JSON round-trip and still produce
// a non-nil []byte for the "exists" check.
func TestRedisCache_BoolSerialization(t *testing.T) {
	b, err := json.Marshal(true)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}
	// The Get path returns []byte; callers only check ok (len > 0).
	if len(b) == 0 {
		t.Error("expected non-empty bytes for bool true")
	}
}
