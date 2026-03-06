package client

import (
	"context"
	"fmt"
	"html"
	"log/slog"
	"net/url"
	"strings"

	chimiddleware "github.com/go-chi/chi/v5/middleware"
)

type AuthEmailSender interface {
	SendVerificationEmail(ctx context.Context, toEmail, displayName, token string) error
	SendPasswordResetEmail(ctx context.Context, toEmail, displayName, token string) error
}

type ResendAuthEmailSender struct {
	resend     *ResendClient
	webBaseURL string
	logger     *slog.Logger
}

type NoopAuthEmailSender struct {
	logger *slog.Logger
}

func NewResendAuthEmailSender(resend *ResendClient, webBaseURL string, logger *slog.Logger) *ResendAuthEmailSender {
	if logger == nil {
		logger = slog.Default()
	}

	return &ResendAuthEmailSender{
		resend:     resend,
		webBaseURL: strings.TrimRight(strings.TrimSpace(webBaseURL), "/"),
		logger:     logger,
	}
}

func NewNoopAuthEmailSender(logger *slog.Logger) *NoopAuthEmailSender {
	if logger == nil {
		logger = slog.Default()
	}

	return &NoopAuthEmailSender{logger: logger}
}

func loggerForContext(ctx context.Context, logger *slog.Logger) *slog.Logger {
	if logger == nil {
		return nil
	}

	if requestID := chimiddleware.GetReqID(ctx); requestID != "" {
		return logger.With(slog.String("request_id", requestID))
	}

	return logger
}

func (s *ResendAuthEmailSender) SendVerificationEmail(ctx context.Context, toEmail, displayName, token string) error {
	verificationURL := s.webBaseURL + "/verify-email?token=" + url.QueryEscape(token)
	safeName := html.EscapeString(strings.TrimSpace(displayName))

	htmlBody := fmt.Sprintf(
		"<p>Hi %s,</p><p>Please verify your Kickoutchi account.</p><p><a href=\"%s\">Verify email</a></p>",
		safeName,
		html.EscapeString(verificationURL),
	)

	textBody := fmt.Sprintf("Hi %s,\n\nVerify your Kickoutchi account: %s\n", safeName, verificationURL)

	messageID, err := s.resend.SendEmail(ctx, toEmail, "Verify your Kickoutchi account", htmlBody, textBody)
	if err != nil {
		return err
	}

	logger := loggerForContext(ctx, s.logger)
	if logger != nil {
		logger.Info("verification_email_sent", slog.String("to_email", toEmail), slog.String("message_id", messageID))
	}
	return nil
}

func (s *ResendAuthEmailSender) SendPasswordResetEmail(ctx context.Context, toEmail, displayName, token string) error {
	resetURL := s.webBaseURL + "/reset-password?token=" + url.QueryEscape(token)
	safeName := html.EscapeString(strings.TrimSpace(displayName))

	htmlBody := fmt.Sprintf(
		"<p>Hi %s,</p><p>Reset your Kickoutchi password.</p><p><a href=\"%s\">Reset password</a></p>",
		safeName,
		html.EscapeString(resetURL),
	)

	textBody := fmt.Sprintf("Hi %s,\n\nReset your password: %s\n", safeName, resetURL)

	messageID, err := s.resend.SendEmail(ctx, toEmail, "Reset your Kickoutchi password", htmlBody, textBody)
	if err != nil {
		return err
	}

	logger := loggerForContext(ctx, s.logger)
	if logger != nil {
		logger.Info("password_reset_email_sent", slog.String("to_email", toEmail), slog.String("message_id", messageID))
	}
	return nil
}

func (s *NoopAuthEmailSender) SendVerificationEmail(ctx context.Context, toEmail, _ string, _ string) error {
	logger := loggerForContext(ctx, s.logger)
	if logger != nil {
		logger.Warn("verification_email_skipped_no_sender", slog.String("to_email", toEmail))
	}
	return nil
}

func (s *NoopAuthEmailSender) SendPasswordResetEmail(ctx context.Context, toEmail, _ string, _ string) error {
	logger := loggerForContext(ctx, s.logger)
	if logger != nil {
		logger.Warn("password_reset_email_skipped_no_sender", slog.String("to_email", toEmail))
	}
	return nil
}
