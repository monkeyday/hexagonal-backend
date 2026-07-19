package metrics

import (
	"expvar"
	"sync"

	coremetrics "sc/core/metrics"
)

// ExpvarRecorder publishes counters via the stdlib expvar package.
// Counters are registered once and reused on subsequent calls.
type ExpvarRecorder struct {
	mu       sync.Mutex
	counters map[string]*expvar.Int
}

func NewExpvarRecorder() *ExpvarRecorder {
	return &ExpvarRecorder{counters: make(map[string]*expvar.Int)}
}

func (r *ExpvarRecorder) Counter(name string) coremetrics.Counter {
	r.mu.Lock()
	defer r.mu.Unlock()
	if c, ok := r.counters[name]; ok {
		return c
	}
	var c *expvar.Int
	if v := expvar.Get(name); v != nil {
		if existing, ok := v.(*expvar.Int); ok {
			c = existing
		} else {
			return coremetrics.NewNoopRecorder().Counter(name)
		}
	} else {
		c = expvar.NewInt(name)
	}
	r.counters[name] = c
	return c
}
