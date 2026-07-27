package define

import "time"

const (
	DefaultExpirySecs  = 900
	MaxTokenExpirySecs = 86400 // 24 hours
	// RevokedGrantMarkerTTL outlives any access token that could have been issued under the grant
	// (see MaxTokenExpirySecs), so the cascade check cannot expire early.
	RevokedGrantMarkerTTL = time.Duration(MaxTokenExpirySecs) * time.Second
	// SessionsInvalidationTTL bounds the user-level invalidation marker. Past
	// MaxTokenExpirySecs every access token issued before the invalidation has expired
	// on its own, so the marker has nothing left to deny (grant-linkage.md §9).
	SessionsInvalidationTTL = time.Duration(MaxTokenExpirySecs) * time.Second
)

func ResolveExpirySecs(requested *int) int {
	if requested == nil || *requested <= 0 {
		return DefaultExpirySecs
	}
	return min(*requested, MaxTokenExpirySecs)
}
