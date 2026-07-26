package define

import "time"

const (
	DefaultExpirySecs  = 900
	MaxTokenExpirySecs = 86400 // 24 hours
	// RevokedGrantMarkerTTL outlives any access token that could have been issued under the grant
	// (see MaxTokenExpirySecs), so the cascade check cannot expire early.
	RevokedGrantMarkerTTL = time.Duration(MaxTokenExpirySecs) * time.Second
)

func ResolveExpirySecs(requested *int) int {
	if requested == nil || *requested <= 0 {
		return DefaultExpirySecs
	}
	return min(*requested, MaxTokenExpirySecs)
}
