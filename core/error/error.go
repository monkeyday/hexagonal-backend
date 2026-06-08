package coreerror

import "errors"

type ErrCode int

const (
	Unauthorized ErrCode = 40001
	Forbidden    ErrCode = 40002
	BadRequest   ErrCode = 40003
	NotFound     ErrCode = 40004
	Internal     ErrCode = 50001
)

var ErrNotFound = errors.New("not found")
var ErrConflict = errors.New("conflict")

var _ Error = (*ErrorStruct)(nil)

type Error interface {
	error
	Code() ErrCode
}

type ErrorStruct struct {
	err        error
	code       ErrCode
	httpStatus int
}

func NewErrorStruct(code ErrCode, httpStatus int, err error) *ErrorStruct {
	return &ErrorStruct{err: err, code: code, httpStatus: httpStatus}
}

func New(code ErrCode, status int, msg string) *ErrorStruct {
	return NewErrorStruct(code, status, errors.New(msg))
}

// NewMsg and NewErr are for domain errors — HTTP status is applied later by the module's error mapper.
func NewMsg(code ErrCode, msg string) *ErrorStruct {
	return &ErrorStruct{err: errors.New(msg), code: code}
}

func NewErr(code ErrCode, err error) *ErrorStruct {
	return &ErrorStruct{err: err, code: code}
}

func (e *ErrorStruct) Error() string   { return e.err.Error() }
func (e *ErrorStruct) Code() ErrCode   { return e.code }
func (e *ErrorStruct) HTTPStatus() int { return e.httpStatus }
func (e *ErrorStruct) Unwrap() error   { return e.err }
