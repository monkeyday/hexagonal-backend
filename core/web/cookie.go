package web

import "net/http"

type Cookie struct {
	Name     string
	Value    string
	MaxAge   int
	SameSite *http.SameSite
}
