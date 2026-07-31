package event

// Event is the envelope carried on the bus.
//
// Payload holds the topic's own named type — never an anonymous struct, which
// a consumer cannot name in order to assert it back.
//
// IdempotencyKey lets a handler recognise a redelivery. It must be minted
// outside uow.Do: the Mongo driver's WithTransaction re-runs the whole callback
// on a transient error, so a key minted inside it differs on every attempt and
// deduplication would never match.
//
// Attempts is the total number of tries a handler gets under Notify (zero and
// one both mean "try once"). Publish ignores it and always tries once, because
// the surrounding transaction may already be retrying.
type Event struct {
	Topic          Topic
	Payload        any
	IdempotencyKey string
	Attempts       int
}
