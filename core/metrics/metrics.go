package metrics

type Counter interface {
	Add(delta int64)
}

type Recorder interface {
	Counter(name string) Counter
}

type noopCounter struct{}

func (noopCounter) Add(_ int64) {}

type noopRecorder struct{}

func (noopRecorder) Counter(_ string) Counter { return noopCounter{} }

func NewNoopRecorder() Recorder { return noopRecorder{} }
