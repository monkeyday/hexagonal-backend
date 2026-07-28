package entity

import "time"

// grantExpiryMargin is how far past a refresh token's own expiry the grant that
// authorises it is kept alive. Nothing about a grant should die before the chain
// it covers, and the two expiries are stamped by different calls, so the margin
// makes the ordering explicit rather than incidental.
const grantExpiryMargin = time.Minute

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
// it generates its own ID and timestamps. ExpiresAt starts as a defensive
// default — a full RefreshTokenTTL window plus the margin — which every issuing
// path then replaces via ExtendToCover once the refresh token it covers exists.
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
		ExpiresAt:       now.Add(RefreshTokenTTL + grantExpiryMargin),
	}
}

func (g *Grant) IsValid() bool {
	return g.RevokedAt == nil && time.Now().Before(g.ExpiresAt)
}

// ExtendToCover pushes the grant's expiry past the expiry of the refresh token
// it authorises. A grant has no natural expiry — rotation renews its chain
// indefinitely — so every issuing path calls this with the expiry of the token
// it just minted, which makes "the grant outlives its chain" hold by
// construction rather than by a clock race (grant-linkage.md §10).
func (g *Grant) ExtendToCover(tokenExpiry time.Time) {
	g.ExpiresAt = tokenExpiry.Add(grantExpiryMargin)
}
