package adapter

import (
	"context"
	"fmt"
	infrasmtp "sc/infrastructure/smtp"

	"github.com/rs/zerolog/log"
)

// LogEmailSender logs emails instead of sending them. Used when SMTP is not configured.
type LogEmailSender struct{}

func NewLogEmailSender() *LogEmailSender { return &LogEmailSender{} }

func (s *LogEmailSender) SendPasswordResetEmail(_ context.Context, toEmail, rawToken string) error {
	log.Info().Str("to", toEmail).Str("token_hint", tokenHint(rawToken)).Msg("password reset email (stub)")
	return nil
}

func tokenHint(token string) string {
	if len(token) <= 8 {
		return token
	}
	return token[:8] + "..."
}

// SmtpEmailSender sends password-reset emails via the persistent SMTP client.
type SmtpEmailSender struct {
	client     *infrasmtp.Client
	appBaseURL string
}

func NewSmtpEmailSender(c *infrasmtp.Client, appBaseURL string) *SmtpEmailSender {
	return &SmtpEmailSender{client: c, appBaseURL: appBaseURL}
}

func (s *SmtpEmailSender) SendPasswordResetEmail(_ context.Context, toEmail, rawToken string) error {
	resetLink := fmt.Sprintf("%s/reset-password?token=%s", s.appBaseURL, rawToken)
	body := fmt.Sprintf(
		"Click the link below to reset your password:\r\n\r\n%s\r\n\r\nThis link expires in 15 minutes.",
		resetLink,
	)
	msg := infrasmtp.BuildMessage(s.client.From, toEmail, "Reset your password", body)
	return s.client.Send([]string{toEmail}, msg)
}
