package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/katsutoo/kickoutchi/api/internal/auth"
	"github.com/katsutoo/kickoutchi/api/internal/client"
	"github.com/katsutoo/kickoutchi/api/internal/config"
	"github.com/katsutoo/kickoutchi/api/internal/database"
	"github.com/katsutoo/kickoutchi/api/internal/handler"
	appmiddleware "github.com/katsutoo/kickoutchi/api/internal/middleware"
	"github.com/katsutoo/kickoutchi/api/internal/repository"
	"github.com/katsutoo/kickoutchi/api/internal/service"
	appvalidator "github.com/katsutoo/kickoutchi/api/internal/validator"
)

type AuthComponents struct {
	Handler              *handler.AuthHandler
	RequireAuth          func(http.Handler) http.Handler
	CSRFProtection       func(http.Handler) http.Handler
	AuthIPRateLimit      func(http.Handler) http.Handler
	AuthAccountRateLimit func(http.Handler) http.Handler
}

func newDatabase(ctx context.Context, cfg config.Config) (*database.DB, error) {
	db, err := database.New(ctx, database.Config{
		URL:               cfg.Database.URL,
		MaxConns:          cfg.Database.MaxConns,
		MinConns:          cfg.Database.MinConns,
		MaxConnLifetime:   cfg.Database.MaxConnLifetime,
		MaxConnIdleTime:   cfg.Database.MaxConnIdleTime,
		HealthCheckPeriod: cfg.Database.HealthCheckPeriod,
		ConnectTimeout:    cfg.Database.ConnectTimeout,
	})
	if err != nil {
		return nil, fmt.Errorf("create database pool: %w", err)
	}

	return db, nil
}

func newAuthComponents(cfg config.Config, db *database.DB, logger *slog.Logger) (AuthComponents, error) {
	if logger == nil {
		logger = slog.Default()
	}

	authRepository := repository.NewAuthRepository(db)
	passwordHasher := auth.NewArgon2Hasher(auth.Argon2Params{
		Memory:     cfg.Argon2.Memory,
		Time:       cfg.Argon2.Time,
		Threads:    cfg.Argon2.Threads,
		KeyLength:  cfg.Argon2.KeyLength,
		SaltLength: cfg.Argon2.SaltLength,
	})

	emailSender := client.AuthEmailSender(client.NewNoopAuthEmailSender(logger))
	if cfg.Resend.APIKey != "" {
		resendClient, err := client.NewResendClient(client.ResendClientConfig{
			APIKey:     cfg.Resend.APIKey,
			FromEmail:  cfg.Resend.FromEmail,
			APIBaseURL: cfg.Resend.APIBaseURL,
		})
		if err != nil {
			return AuthComponents{}, fmt.Errorf("create resend client: %w", err)
		}

		emailSender = client.NewResendAuthEmailSender(resendClient, cfg.WebBaseURL, logger)
	}

	var githubOAuthClient *client.GitHubOAuthClient
	if cfg.OAuth.GitHubClientID != "" {
		createdGitHubOAuthClient, err := client.NewGitHubOAuthClient(client.GitHubOAuthClientConfig{
			ClientID:     cfg.OAuth.GitHubClientID,
			ClientSecret: cfg.OAuth.GitHubClientSecret,
			RedirectURL:  cfg.OAuth.GitHubRedirectURL,
		})
		if err != nil {
			return AuthComponents{}, fmt.Errorf("create github oauth client: %w", err)
		}

		githubOAuthClient = createdGitHubOAuthClient
	}

	var avatarStorage *client.R2Client
	if cfg.R2.AccountID != "" {
		createdR2Client, err := client.NewR2Client(client.R2ClientConfig{
			AccountID:       cfg.R2.AccountID,
			Bucket:          cfg.R2.Bucket,
			AccessKeyID:     cfg.R2.AccessKeyID,
			SecretAccessKey: cfg.R2.SecretAccessKey,
			Region:          cfg.R2.Region,
			PublicBaseURL:   cfg.R2.PublicBaseURL,
			SignedUploadTTL: cfg.R2.SignedUploadTTL,
		})
		if err != nil {
			return AuthComponents{}, fmt.Errorf("create r2 client: %w", err)
		}

		avatarStorage = createdR2Client
	}

	authService := service.NewAuthService(
		authRepository,
		passwordHasher,
		emailSender,
		githubOAuthClient,
		avatarStorage,
		cfg.Session.TTL,
		cfg.Session.RefreshWindow,
		cfg.Auth.PasswordResetTokenTTL,
		cfg.Auth.EmailVerificationTokenTTL,
		cfg.R2.SignedUploadTTL,
	)
	validator := appvalidator.New()
	cookieConfig := handler.SessionCookieConfig{
		Name:     cfg.Session.CookieName,
		Domain:   cfg.Session.CookieDomain,
		Secure:   cfg.Session.CookieSecure,
		SameSite: cfg.Session.CookieSameSite,
		TTL:      cfg.Session.TTL,
	}

	authHandler := handler.NewAuthHandler(
		authService,
		validator,
		cookieConfig,
		cfg.WebBaseURL,
		cfg.Auth.OAuthStateTTL,
	)
	requireAuth := appmiddleware.RequireAuth(authService, appmiddleware.SessionCookieConfig{
		Name:     cfg.Session.CookieName,
		Domain:   cfg.Session.CookieDomain,
		Secure:   cfg.Session.CookieSecure,
		SameSite: cfg.Session.CookieSameSite,
		TTL:      cfg.Session.TTL,
	})

	csrfProtection := appmiddleware.CSRFOriginCheck(appmiddleware.CSRFConfig{
		AllowedOrigins: cfg.Security.CSRFAllowedOrigins,
	})

	authIPRateLimiter := appmiddleware.RateLimitByIP(appmiddleware.NewKeyRateLimiter(
		cfg.Security.AuthIPRateLimitRequests,
		cfg.Security.AuthIPRateLimitWindow,
		cfg.Security.AuthIPRateLimitBurst,
	))

	authAccountRateLimiter := appmiddleware.RateLimitByJSONField(appmiddleware.NewKeyRateLimiter(
		cfg.Security.AuthAccountRateLimitRequests,
		cfg.Security.AuthAccountRateLimitWindow,
		cfg.Security.AuthAccountRateLimitBurst,
	), "email")

	return AuthComponents{
		Handler:              authHandler,
		RequireAuth:          requireAuth,
		CSRFProtection:       csrfProtection,
		AuthIPRateLimit:      authIPRateLimiter,
		AuthAccountRateLimit: authAccountRateLimiter,
	}, nil
}
