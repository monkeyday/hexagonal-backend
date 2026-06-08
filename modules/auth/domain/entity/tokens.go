package entity

import (
	"crypto/sha256"
	"encoding/hex"
	"time"

	"github.com/google/uuid"
)

const RefreshTokenTTL = 30 * 24 * time.Hour

type IssuedTokens struct {
	AccessToken  string
	RefreshToken string
	IDToken      string
	Scope        Scope
}
type RefreshToken struct {
	ID              string
	UserID          UserID
	TokenHash       string
	Scope           Scope
	DeviceID        string
	AuthenticatedAt time.Time // set once at original authentication; preserved across rotations
	CreatedAt       time.Time
	ExpiresAt       time.Time
	RevokedAt       *time.Time
}

func NewRefreshToken(userID UserID, tokens *IssuedTokens) *RefreshToken {
	now := time.Now()
	return &RefreshToken{
		ID:              uuid.NewString(),
		UserID:          userID,
		TokenHash:       Hash(tokens.RefreshToken),
		Scope:           tokens.Scope,
		AuthenticatedAt: now,
		CreatedAt:       now,
		ExpiresAt:       now.Add(RefreshTokenTTL),
	}
}

// Rotate creates a new RefreshToken for token rotation, carrying forward the stable
// AuthenticatedAt and DeviceID from the original authentication event.
func (rt *RefreshToken) Rotate(userID UserID, tokens *IssuedTokens) *RefreshToken {
	n := NewRefreshToken(userID, tokens)
	n.AuthenticatedAt = rt.AuthenticatedAt
	n.DeviceID = rt.DeviceID
	return n
}

func (rt *RefreshToken) IsValid() bool {
	return rt.RevokedAt == nil && time.Now().Before(rt.ExpiresAt)
}

func Hash(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}
