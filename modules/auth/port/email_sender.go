package port

import "context"

type EmailSender interface {
	SendPasswordResetEmail(ctx context.Context, toEmail, rawToken string) error
}
