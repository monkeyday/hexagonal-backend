package eventbus

import (
	"context"
	"errors"
	"sc/core/event"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const (
	topicA = event.Topic("test.a")
	topicB = event.Topic("test.b")

	// settleTimeout bounds how long a test waits for a Notify goroutine before
	// declaring it stuck.
	settleTimeout = 2 * time.Second
)

var errHandler = errors.New("handler failed")

// waitFor polls until done reports true, so an asynchronous delivery does not
// need a fixed sleep.
func waitFor(t *testing.T, done func() bool) {
	t.Helper()
	deadline := time.Now().Add(settleTimeout)
	for time.Now().Before(deadline) {
		if done() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("condition not met within %s", settleTimeout)
}

func TestPublish(t *testing.T) {
	tests := []struct {
		name        string
		handlers    []func(*[]string) event.Handler
		wantCalls   []string
		wantErr     bool
		errContains []string
	}{
		{
			name:      "no subscribers — nil error",
			wantCalls: nil,
		},
		{
			name: "single handler runs and succeeds",
			handlers: []func(*[]string) event.Handler{
				func(calls *[]string) event.Handler {
					return func(context.Context, event.Event) error {
						*calls = append(*calls, "one")
						return nil
					}
				},
			},
			wantCalls: []string{"one"},
		},
		{
			name: "handlers run in subscription order on the calling goroutine",
			handlers: []func(*[]string) event.Handler{
				func(calls *[]string) event.Handler {
					return func(context.Context, event.Event) error {
						*calls = append(*calls, "first")
						return nil
					}
				},
				func(calls *[]string) event.Handler {
					return func(context.Context, event.Event) error {
						*calls = append(*calls, "second")
						return nil
					}
				},
			},
			wantCalls: []string{"first", "second"},
		},
		{
			name: "every handler still runs when an earlier one fails",
			handlers: []func(*[]string) event.Handler{
				func(calls *[]string) event.Handler {
					return func(context.Context, event.Event) error {
						*calls = append(*calls, "failing")
						return errHandler
					}
				},
				func(calls *[]string) event.Handler {
					return func(context.Context, event.Event) error {
						*calls = append(*calls, "surviving")
						return nil
					}
				},
			},
			wantCalls:   []string{"failing", "surviving"},
			wantErr:     true,
			errContains: []string{"sub-0"},
		},
		{
			name: "errors from several handlers are joined, each labelled",
			handlers: []func(*[]string) event.Handler{
				func(calls *[]string) event.Handler {
					return func(context.Context, event.Event) error {
						*calls = append(*calls, "a")
						return errors.New("boom a")
					}
				},
				func(calls *[]string) event.Handler {
					return func(context.Context, event.Event) error {
						*calls = append(*calls, "b")
						return errors.New("boom b")
					}
				},
			},
			wantCalls:   []string{"a", "b"},
			wantErr:     true,
			errContains: []string{"sub-0", "boom a", "sub-1", "boom b"},
		},
		{
			name: "a panicking handler becomes an error, not a crash",
			handlers: []func(*[]string) event.Handler{
				func(calls *[]string) event.Handler {
					return func(context.Context, event.Event) error {
						*calls = append(*calls, "panicking")
						panic("handler exploded")
					}
				},
			},
			wantCalls:   []string{"panicking"},
			wantErr:     true,
			errContains: []string{"panic in event handler", "handler exploded"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := New()
			// calls is an ordinary slice with no mutex: if Publish ever ran
			// handlers concurrently, -race would report a data race here.
			var calls []string
			for i, h := range tt.handlers {
				b.Subscribe(topicA, "sub-"+string(rune('0'+i)), h(&calls))
			}

			err := b.Publish(context.Background(), event.Event{Topic: topicA})

			if tt.wantErr && err == nil {
				t.Fatal("expected an error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			for _, want := range tt.errContains {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error %q does not contain %q", err, want)
				}
			}
			if len(calls) != len(tt.wantCalls) {
				t.Fatalf("calls = %v, want %v", calls, tt.wantCalls)
			}
			for i, want := range tt.wantCalls {
				if calls[i] != want {
					t.Errorf("call %d = %q, want %q", i, calls[i], want)
				}
			}
		})
	}
}

// TestPublishFromWithinHandler covers the case that made the earlier draft
// deadlock: it held the bus mutex across handler execution, so a handler that
// published could never acquire it.
func TestPublishFromWithinHandler(t *testing.T) {
	b := New()

	var inner atomic.Bool
	b.Subscribe(topicA, "outer", func(ctx context.Context, _ event.Event) error {
		return b.Publish(ctx, event.Event{Topic: topicB})
	})
	b.Subscribe(topicB, "inner", func(context.Context, event.Event) error {
		inner.Store(true)
		return nil
	})

	done := make(chan error, 1)
	go func() { done <- b.Publish(context.Background(), event.Event{Topic: topicA}) }()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	case <-time.After(settleTimeout):
		t.Fatal("Publish deadlocked when a handler published from inside it")
	}
	if !inner.Load() {
		t.Error("the nested handler never ran")
	}
}

func TestPublishStopsAtMaxDepth(t *testing.T) {
	b := New()

	var depth atomic.Int32
	b.Subscribe(topicA, "recursive", func(ctx context.Context, evt event.Event) error {
		depth.Add(1)
		return b.Publish(ctx, evt)
	})

	done := make(chan error, 1)
	go func() { done <- b.Publish(context.Background(), event.Event{Topic: topicA}) }()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected a depth-limit error, got nil")
		}
		if !strings.Contains(err.Error(), "max publish depth") {
			t.Errorf("error %q does not mention the depth limit", err)
		}
	case <-time.After(settleTimeout):
		t.Fatal("a self-publishing handler never terminated")
	}

	if got := depth.Load(); int(got) > maxDepth {
		t.Errorf("handler ran %d times, want at most maxDepth=%d", got, maxDepth)
	}
}

func TestNotify(t *testing.T) {
	t.Run("handler errors never reach the caller", func(t *testing.T) {
		b := New()
		var called atomic.Bool
		b.Subscribe(topicA, "failing", func(context.Context, event.Event) error {
			called.Store(true)
			return errHandler
		})

		// Notify returns no error at all — the compiler enforces that the
		// caller cannot depend on handler failure.
		b.Notify(context.Background(), event.Event{Topic: topicA})

		waitFor(t, called.Load)
	})

	t.Run("delivery survives cancellation of the caller's context", func(t *testing.T) {
		b := New()
		var called atomic.Bool
		release := make(chan struct{})
		b.Subscribe(topicA, "detached", func(ctx context.Context, _ event.Event) error {
			<-release
			if ctx.Err() != nil {
				return ctx.Err()
			}
			called.Store(true)
			return nil
		})

		ctx, cancel := context.WithCancel(context.Background())
		b.Notify(ctx, event.Event{Topic: topicA})
		cancel()
		close(release)

		waitFor(t, called.Load)
	})

	t.Run("Attempts drives retries and stops once a handler succeeds", func(t *testing.T) {
		b := New()
		var attempts atomic.Int32
		b.Subscribe(topicA, "flaky", func(context.Context, event.Event) error {
			if attempts.Add(1) < 3 {
				return errHandler
			}
			return nil
		})

		b.Notify(context.Background(), event.Event{Topic: topicA, Attempts: 5})

		waitFor(t, func() bool { return attempts.Load() == 3 })
		time.Sleep(50 * time.Millisecond)
		if got := attempts.Load(); got != 3 {
			t.Errorf("handler ran %d times, want 3 — it should stop on success", got)
		}
	})

	t.Run("a zero Attempts means exactly one try", func(t *testing.T) {
		b := New()
		var attempts atomic.Int32
		b.Subscribe(topicA, "always-fails", func(context.Context, event.Event) error {
			attempts.Add(1)
			return errHandler
		})

		b.Notify(context.Background(), event.Event{Topic: topicA})

		waitFor(t, func() bool { return attempts.Load() == 1 })
		time.Sleep(50 * time.Millisecond)
		if got := attempts.Load(); got != 1 {
			t.Errorf("handler ran %d times, want 1", got)
		}
	})

	t.Run("a panicking handler does not take the process down", func(t *testing.T) {
		b := New()
		var called atomic.Bool
		b.Subscribe(topicA, "panicking", func(context.Context, event.Event) error {
			called.Store(true)
			panic("handler exploded")
		})

		b.Notify(context.Background(), event.Event{Topic: topicA})

		waitFor(t, called.Load)
	})
}

// TestNotifyDropsWhenSaturated pins the backpressure choice: a full bus drops
// the delivery and logs it, rather than queueing goroutines without limit.
func TestNotifyDropsWhenSaturated(t *testing.T) {
	b := newWithLimits(1, 20*time.Millisecond)

	release := make(chan struct{})
	var started, finished atomic.Int32
	b.Subscribe(topicA, "blocking", func(context.Context, event.Event) error {
		started.Add(1)
		<-release
		finished.Add(1)
		return nil
	})

	// The first delivery takes the only slot and parks there.
	b.Notify(context.Background(), event.Event{Topic: topicA})
	waitFor(t, func() bool { return started.Load() == 1 })

	// The second cannot acquire within the timeout and must be dropped.
	b.Notify(context.Background(), event.Event{Topic: topicA})
	time.Sleep(60 * time.Millisecond)
	if got := started.Load(); got != 1 {
		t.Errorf("%d deliveries started, want 1 — the second should have been dropped", got)
	}

	// Freeing the slot is what separates "dropped" from "queued": an
	// implementation that parked the second delivery on the semaphore instead
	// of dropping it would start it now.
	close(release)
	waitFor(t, func() bool { return finished.Load() == 1 })
	time.Sleep(60 * time.Millisecond)
	if got := started.Load(); got != 1 {
		t.Errorf("%d deliveries started after the slot was freed, want 1 — the dropped delivery must not be queued", got)
	}
	if got := finished.Load(); got != 1 {
		t.Errorf("%d deliveries finished, want 1", got)
	}
}

func TestSubscribeCommandLabelsWithTheCommandType(t *testing.T) {
	b := New()
	d := &stubDispatcher{err: errHandler}
	SubscribeCommand[stubCommand](b, topicA, d)

	err := b.Publish(context.Background(), event.Event{Topic: topicA, Payload: "x"})
	if err == nil {
		t.Fatal("expected an error, got nil")
	}
	// The label is derived from T, so it cannot drift from the command it names.
	if !strings.Contains(err.Error(), "eventbus.stubCommand") {
		t.Errorf("error %q does not carry the command type as its label", err)
	}
}

func TestPublishRunsHandlersOfOneTopicOnly(t *testing.T) {
	b := New()
	var a, other atomic.Int32
	b.Subscribe(topicA, "a", func(context.Context, event.Event) error { a.Add(1); return nil })
	b.Subscribe(topicB, "b", func(context.Context, event.Event) error { other.Add(1); return nil })

	if err := b.Publish(context.Background(), event.Event{Topic: topicA}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if a.Load() != 1 || other.Load() != 0 {
		t.Errorf("topicA=%d topicB=%d, want 1 and 0", a.Load(), other.Load())
	}
}

func TestSubscribeIsSafeUnderConcurrentPublish(t *testing.T) {
	b := New()
	b.Subscribe(topicA, "seed", func(context.Context, event.Event) error { return nil })

	var wg sync.WaitGroup
	for i := range 50 {
		wg.Add(2)
		go func() {
			defer wg.Done()
			b.Subscribe(topicA, "late-"+string(rune('0'+i%10)), func(context.Context, event.Event) error { return nil })
		}()
		go func() {
			defer wg.Done()
			_ = b.Publish(context.Background(), event.Event{Topic: topicA})
		}()
	}
	wg.Wait()
}

// --- Handle ---------------------------------------------------------------

type stubCommand struct {
	Token string
}

func (c *stubCommand) UnmarshalEvent(evt event.Event) error {
	payload, ok := evt.Payload.(string)
	if !ok {
		return errors.New("unexpected payload type")
	}
	c.Token = payload
	return nil
}

type panickingCommand struct{}

func (c *panickingCommand) UnmarshalEvent(event.Event) error {
	panic("unmarshal exploded")
}

type stubDispatcher struct {
	got  any
	err  error
	hits int
}

func (d *stubDispatcher) Dispatch(_ context.Context, cmd any) (any, error) {
	d.hits++
	d.got = cmd
	return nil, d.err
}

func TestHandle(t *testing.T) {
	t.Run("builds the command from the event and dispatches it", func(t *testing.T) {
		d := &stubDispatcher{}
		h := Handle[stubCommand](d)

		if err := h(context.Background(), event.Event{Topic: topicA, Payload: "reset-token"}); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if d.hits != 1 {
			t.Fatalf("dispatched %d times, want 1", d.hits)
		}
		cmd, ok := d.got.(*stubCommand)
		if !ok {
			t.Fatalf("dispatched %T, want *stubCommand", d.got)
		}
		if cmd.Token != "reset-token" {
			t.Errorf("Token = %q, want %q", cmd.Token, "reset-token")
		}
	})

	t.Run("an unmarshal failure is reported and nothing is dispatched", func(t *testing.T) {
		d := &stubDispatcher{}
		h := Handle[stubCommand](d)

		err := h(context.Background(), event.Event{Topic: topicA, Payload: 42})
		if err == nil {
			t.Fatal("expected an error, got nil")
		}
		if d.hits != 0 {
			t.Errorf("dispatched %d times, want 0", d.hits)
		}
	})

	t.Run("a dispatch failure propagates", func(t *testing.T) {
		d := &stubDispatcher{err: errHandler}
		h := Handle[stubCommand](d)

		if err := h(context.Background(), event.Event{Topic: topicA, Payload: "x"}); !errors.Is(err, errHandler) {
			t.Fatalf("error = %v, want %v", err, errHandler)
		}
	})

	// UnmarshalEvent runs before Registry.Dispatch's own recover is reached, so
	// the bus has to catch this one itself.
	t.Run("a panic in UnmarshalEvent is contained by the bus", func(t *testing.T) {
		b := New()
		d := &stubDispatcher{}
		b.Subscribe(topicA, "panicking-unmarshal", Handle[panickingCommand](d))

		err := b.Publish(context.Background(), event.Event{Topic: topicA})
		if err == nil {
			t.Fatal("expected an error, got nil")
		}
		if !strings.Contains(err.Error(), "unmarshal exploded") {
			t.Errorf("error %q does not mention the panic", err)
		}
		if d.hits != 0 {
			t.Errorf("dispatched %d times, want 0", d.hits)
		}
	})
}
