// Package random produces cryptographically secure random values.
package random

import (
	"crypto/rand"
	"encoding/base64"
)

// TokenBytes is the entropy (256 bits) behind every secret token the
// application generates: refresh tokens, auth codes, CSRF tokens, reset tokens.
const TokenBytes = 32

// Token returns a URL-safe, unpadded base64 string of TokenBytes random bytes.
func Token() (string, error) {
	b := make([]byte, TokenBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
