package entity

import "time"

// Grant is the aggregate root for one authentication event: the linkage that
// access tokens carry as their sid claim and that refresh tokens belong to. It
// exists so grant-level state (revocation, expiry) has a durable home instead
// of living denormalised across RefreshToken rows (grant-linkage.md §10).
type Grant struct {
	ID              GrantID
	UserID          UserID
	ClientID        ClientID // empty when the grant had no authenticated client (password grant)
	DeviceID        string
	AuthenticatedAt time.Time
	CreatedAt       time.Time
	ExpiresAt       time.Time
	RevokedAt       *time.Time
}

// NewGrant mints a grant for a new authentication event. Like NewRefreshToken
// it generates its own ID and timestamps. ExpiresAt is a fixed RefreshTokenTTL
// window from the authentication event and is never extended here: a rotated
// RefreshToken gets a fresh TTL, so a long-lived chain will outlive its grant
// until rotation starts extending ExpiresAt (grant-linkage.md §10, PR8).
// DeviceID is filled in once client support is established (exchange_code.go:27).
//
// The returned grant's ID feeds both the access-token sid claim and the
// IssuedTokens.GrantID field, so the persisted grant and the sid claim
// cannot diverge.
func NewGrant(userID UserID, clientID ClientID) *Grant {
	now := time.Now()
	return &Grant{
		ID:              NewGrantID(),
		UserID:          userID,
		ClientID:        clientID,
		AuthenticatedAt: now,
		CreatedAt:       now,
		ExpiresAt:       now.Add(RefreshTokenTTL),
	}
}

func (g *Grant) IsValid() bool {
	return g.RevokedAt == nil && time.Now().Before(g.ExpiresAt)
}
