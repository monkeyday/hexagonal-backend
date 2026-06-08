package adapter

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

func TestTokenHint(t *testing.T) {
	tests := []struct {
		name  string
		token string
		want  string
	}{
		{"empty", "", ""},
		{"seven chars", "1234567", "1234567"},
		{"exactly eight chars", "12345678", "12345678"},
		{"nine chars", "123456789", "12345678..."},
		{"long token", "abcdefghijklmnop", "abcdefgh..."},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := tokenHint(tc.token)
			if got != tc.want {
				t.Errorf("tokenHint(%q) = %q, want %q", tc.token, got, tc.want)
			}
		})
	}
}

func TestLogEmailSender(t *testing.T) {
	const rawToken = "supersecretresettoken123"
	const wantHint = "supersec..."

	var buf bytes.Buffer
	orig := log.Logger
	log.Logger = zerolog.New(&buf)
	defer func() { log.Logger = orig }()

	s := NewLogEmailSender()
	if err := s.SendPasswordResetEmail(context.Background(), "user@example.com", rawToken); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	logged := buf.String()
	if strings.Contains(logged, rawToken) {
		t.Error("raw token must not appear in logs")
	}
	if !strings.Contains(logged, wantHint) {
		t.Errorf("expected token hint %q in logs, got: %s", wantHint, logged)
	}
}
