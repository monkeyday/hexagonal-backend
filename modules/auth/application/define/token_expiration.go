package define

const (
	DefaultExpirySecs  = 900
	MaxTokenExpirySecs = 86400 // 24 hours
)

func ResolveExpirySecs(requested *int) int {
	if requested == nil || *requested <= 0 {
		return DefaultExpirySecs
	}
	return min(*requested, MaxTokenExpirySecs)
}
