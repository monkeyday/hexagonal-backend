package eventbus

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sc/core/event"
	"sc/core/usecase"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
)

const (
	// maxConcurrent caps how many Notify handlers run at once. Publish is
	// sequential and is not subject to it.
	maxConcurrent = 100

	// acquireTimeout bounds how long Notify waits for a slot before dropping
	// the delivery. Blocking indefinitely would turn a saturated bus into a
	// stalled request path.
	acquireTimeout = 5 * time.Second

	// handlerTimeout bounds one Notify delivery, retries included. The detached
	// context is deliberately immune to the caller's cancellation, so without a
	// deadline of its own a handler stuck on I/O could never be stopped — not
	// even by shutdown. The bus carries short work; anything slower belongs on
	// the task queue.
	handlerTimeout = 30 * time.Second

	// retryBaseBackoff is doubled on each further attempt. Retrying with no
	// pause almost always reproduces the same transient failure.
	retryBaseBackoff = 100 * time.Millisecond

	// maxDepth bounds publish-within-handler recursion. A cycle (A publishes B,
	// B publishes A) would otherwise loop until the process dies, and no test
	// reliably catches it.
	maxDepth = 8
)

type depthKey struct{}

var (
	_ event.Publisher  = (*InMemory)(nil)
	_ event.Subscriber = (*InMemory)(nil)
)

type subscription struct {
	label string
	fn    event.Handler
}

// InMemory is an in-process, at-most-once event bus: subscriptions live only in
// this process and nothing survives a restart. Work that must not be lost
// belongs on the task queue, not here.
type InMemory struct {
	mu             sync.RWMutex
	handlers       map[event.Topic][]subscription
	semaphore      chan struct{}
	acquireTimeout time.Duration
}

func New() *InMemory {
	return newWithLimits(maxConcurrent, acquireTimeout)
}

// newWithLimits exists so tests can saturate the bus without queueing a hundred
// handlers or waiting out the production acquire timeout.
func newWithLimits(concurrent int, timeout time.Duration) *InMemory {
	return &InMemory{
		handlers:       make(map[event.Topic][]subscription),
		semaphore:      make(chan struct{}, concurrent),
		acquireTimeout: timeout,
	}
}

func (b *InMemory) Subscribe(t event.Topic, label string, fn event.Handler) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.handlers[t] = append(b.handlers[t], subscription{label: label, fn: fn})
}

// handlersFor copies the subscriptions under a read lock so that dispatch runs
// with the lock released. Holding it across handler execution would serialise
// every publisher, and would deadlock outright on a handler that publishes.
func (b *InMemory) handlersFor(t event.Topic) []subscription {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return append([]subscription(nil), b.handlers[t]...)
}

func (b *InMemory) Publish(ctx context.Context, evt event.Event) error {
	subs := b.handlersFor(evt.Topic)
	if len(subs) == 0 {
		return nil
	}

	ctx, err := descend(ctx, evt.Topic)
	if err != nil {
		return err
	}

	var errs []error
	for _, s := range subs {
		if err := b.invoke(ctx, evt, s); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", s.label, err))
		}
	}
	return errors.Join(errs...)
}

func (b *InMemory) Notify(ctx context.Context, evt event.Event) {
	subs := b.handlersFor(evt.Topic)
	if len(subs) == 0 {
		return
	}

	// Detach from the caller's cancellation: a fire-and-forget delivery must
	// outlive the request that triggered it.
	base, err := descend(context.WithoutCancel(ctx), evt.Topic)
	if err != nil {
		log.Error().Err(err).Str("topic", string(evt.Topic)).Msg("eventbus: notify rejected")
		return
	}

	for _, s := range subs {
		// Acquire before starting the goroutine: taking the slot inside it
		// would bound concurrency but let goroutines queue without limit.
		if !b.acquire() {
			log.Error().
				Str("topic", string(evt.Topic)).
				Str("subscription", s.label).
				Msg("eventbus: dropped delivery, no slot available")
			continue
		}
		go func(s subscription) {
			defer func() { <-b.semaphore }()
			// One deadline per delivery, so a slow handler cannot spend a
			// sibling's budget.
			ctx, cancel := context.WithTimeout(base, handlerTimeout)
			defer cancel()
			b.deliver(ctx, evt, s)
		}(s)
	}
}

// acquire waits for a slot, bounded only by acquireTimeout. It deliberately
// does not watch the caller's context: that context is cancelled the moment the
// request finishes, which is exactly when a fire-and-forget delivery still
// needs to go out.
func (b *InMemory) acquire() bool {
	timer := time.NewTimer(b.acquireTimeout)
	defer timer.Stop()
	select {
	case b.semaphore <- struct{}{}:
		return true
	case <-timer.C:
		return false
	}
}

// deliver retries a Notify handler up to evt.Attempts times with exponential
// backoff, then gives up and logs. Retrying assumes the handler is idempotent;
// the publisher opts in by setting Attempts.
func (b *InMemory) deliver(ctx context.Context, evt event.Event, s subscription) {
	attempts := max(evt.Attempts, 1)

	for i := range attempts {
		err := b.invoke(ctx, evt, s)
		if err == nil {
			return
		}
		if i == attempts-1 {
			log.Error().Err(err).
				Str("topic", string(evt.Topic)).
				Str("subscription", s.label).
				Int("attempts", attempts).
				Msg("eventbus: handler failed")
			return
		}

		timer := time.NewTimer(retryBaseBackoff << i)
		select {
		case <-ctx.Done():
			timer.Stop()
			log.Error().Err(ctx.Err()).
				Str("topic", string(evt.Topic)).
				Str("subscription", s.label).
				Msg("eventbus: retry abandoned")
			return
		case <-timer.C:
		}
	}
}

// invoke converts a panicking handler into an error. Registry.Dispatch already
// recovers panics inside a use case, but a command's UnmarshalEvent runs before
// Dispatch is reached and would otherwise take the process down.
func (b *InMemory) invoke(ctx context.Context, evt event.Event, s subscription) (err error) {
	defer func() {
		if rec := recover(); rec != nil {
			err = fmt.Errorf("panic in event handler %q: %v", s.label, rec)
		}
	}()
	return s.fn(ctx, evt)
}

func descend(ctx context.Context, t event.Topic) (context.Context, error) {
	depth, _ := ctx.Value(depthKey{}).(int)
	if depth >= maxDepth {
		return nil, fmt.Errorf("event %q exceeded max publish depth %d", t, maxDepth)
	}
	return context.WithValue(ctx, depthKey{}, depth+1), nil
}

// SubscribeCommand binds a topic to the use case that handles T, labelling the
// subscription with T's own type name. Deriving the label means it can never
// drift from the command it names, the way a hand-written string would.
//
// It is a function rather than a method because Go has no generic methods.
func SubscribeCommand[T any, PT interface {
	*T
	event.Unmarshaler
}](s event.Subscriber, t event.Topic, d usecase.Dispatcher) {
	s.Subscribe(t, reflect.TypeFor[T]().String(), Handle[T, PT](d))
}

// Handle adapts a command to a Handler: it builds the command from the event
// and dispatches it. PT constrains *T to Unmarshaler, so a command that cannot
// be built from an event fails to compile rather than at runtime.
//
// Prefer SubscribeCommand; reach for Handle directly only when the handler is
// not being registered through a Subscriber.
func Handle[T any, PT interface {
	*T
	event.Unmarshaler
}](d usecase.Dispatcher) event.Handler {
	return func(ctx context.Context, evt event.Event) error {
		cmd := PT(new(T))
		if err := cmd.UnmarshalEvent(evt); err != nil {
			return err
		}
		_, err := d.Dispatch(ctx, cmd)
		return err
	}
}
