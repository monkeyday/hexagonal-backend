package event

// Topic names a kind of event. Each topic owns one payload type; see payload
// documentation on the constant that declares it.
type Topic string

const (
	EmailSent = Topic("email_sent")
)
