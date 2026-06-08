package repository

type ErrWriteFailed struct{ cause error }

func NewErrWriteFailed(cause error) *ErrWriteFailed { return &ErrWriteFailed{cause} }
func (e *ErrWriteFailed) Error() string             { return "repository: write failed: " + e.cause.Error() }
func (e *ErrWriteFailed) Unwrap() error             { return e.cause }

type ErrReadFailed struct{ cause error }

func NewErrReadFailed(cause error) *ErrReadFailed { return &ErrReadFailed{cause} }
func (e *ErrReadFailed) Error() string            { return "repository: read failed: " + e.cause.Error() }
func (e *ErrReadFailed) Unwrap() error            { return e.cause }

type ErrInitFailed struct{ cause error }

func NewErrInitFailed(cause error) *ErrInitFailed { return &ErrInitFailed{cause} }
func (e *ErrInitFailed) Error() string            { return "repository: init failed: " + e.cause.Error() }
func (e *ErrInitFailed) Unwrap() error            { return e.cause }

type ErrInvalidField struct{ cause error }

func NewErrInvalidField(cause error) *ErrInvalidField { return &ErrInvalidField{cause} }
func (e *ErrInvalidField) Error() string              { return "repository: invalid field: " + e.cause.Error() }
func (e *ErrInvalidField) Unwrap() error              { return e.cause }

type Repository[T any] interface {
	FindByField(field string, value string) (*T, error)
	Save(item *T) error
}
