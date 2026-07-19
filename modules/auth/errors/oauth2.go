package autherrors

import (
	coreerror "sc/core/error"
)

// HTTPError wraps a mapped error so it carries both an HTTP status and an
// RFC 6749 error code. The responder renders the RFC body on OAuth2 routes and
// falls back to the default {"msg","err_code"} shape elsewhere.
type HTTPError struct {
	*coreerror.ErrorStruct
}

func (e HTTPError) OAuth2Code() string        { return OAuth2CodeFor(e.Code()) }
func (e HTTPError) OAuth2Description() string { return e.Error() }
