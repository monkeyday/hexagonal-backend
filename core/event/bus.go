package event

import "context"

// Publisher is a driven port: the use case reaching out to announce a fact.
// It is injected through define.Dependencies alongside the repositories.
type Publisher interface {
	// Publish runs every handler synchronously and in sequence on ctx, and
	// returns their joined error.
	//
	// Safe to call inside uow.Do: handlers receive the transaction's context
	// and join it, so a handler failure can roll the whole unit back. That is
	// also why it runs sequentially — a Mongo session must not be used from
	// two goroutines at once — and why it never retries: WithTransaction may
	// already be re-running the entire callback.
	Publish(ctx context.Context, evt Event) error

	// Notify runs handlers asynchronously on a context detached from ctx's
	// cancellation, retries them per evt.Attempts, and reports nothing back to
	// the caller: failures are logged.
	//
	// Must NOT be called inside uow.Do. The transaction's session is ended when
	// Do returns, and context.WithoutCancel only strips cancellation — it
	// preserves values, so the dead session would still be found on the ctx.
	// Call it after Do has returned, with the use case's own context.
	Notify(ctx context.Context, evt Event)
}

// Subscriber is a driving port: how the delivery layer registers the use cases
// an event may drive. It is handed to adapter/in at wiring time, mirroring the
// way RegisterRoutes receives the HTTP engine. A use case must never hold one.
type Subscriber interface {
	// Subscribe registers fn for t. The label identifies the subscription in
	// error logs, since a func value carries no name of its own.
	Subscribe(t Topic, label string, fn Handler)
}

// Handler consumes one event. It reports failure so the bus can retry or log;
// any result belongs to the use case, not to the publisher.
type Handler func(ctx context.Context, evt Event) error

// Unmarshaler is implemented by a command that can populate itself from an
// event, mirroring json.Unmarshaler. Implement it on the pointer receiver.
type Unmarshaler interface {
	UnmarshalEvent(evt Event) error
}
