package testutil

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/katsutoo/kickoutchi/api/internal/auth"
	"github.com/katsutoo/kickoutchi/api/internal/handler"
	appmiddleware "github.com/katsutoo/kickoutchi/api/internal/middleware"
	"github.com/katsutoo/kickoutchi/api/internal/repository"
	"github.com/katsutoo/kickoutchi/api/internal/router"
	"github.com/katsutoo/kickoutchi/api/internal/service"
	appvalidator "github.com/katsutoo/kickoutchi/api/internal/validator"
)

const defaultAllowedOrigin = "http://web.test"

type IntegrationAppOptions struct {
	AllowedOrigin                string
	AuthIPRateLimitRequests      int
	AuthIPRateLimitWindow        time.Duration
	AuthIPRateLimitBurst         int
	AuthAccountRateLimitRequests int
	AuthAccountRateLimitWindow   time.Duration
	AuthAccountRateLimitBurst    int
}

type IntegrationApp struct {
	BaseURL        string
	AllowedOrigin  string
	EmailSender    *CapturingAuthEmailSender
	AuthRepository *repository.AuthRepository
	AuthService    *service.AuthService

	server *httptest.Server
}

type CapturingAuthEmailSender struct {
	mu                  sync.Mutex
	verificationTokens  map[string]string
	passwordResetTokens map[string]string
}

func NewIntegrationApp(t *testing.T, options IntegrationAppOptions) *IntegrationApp {
	t.Helper()

	normalizedOptions := options.withDefaults()
	db := NewDatabase(t)

	authRepository := repository.NewAuthRepository(db)
	passwordHasher := auth.NewArgon2Hasher(auth.Argon2Params{
		Memory:     1024,
		Time:       1,
		Threads:    1,
		KeyLength:  32,
		SaltLength: 16,
	})

	emailSender := NewCapturingAuthEmailSender()

	authService := service.NewAuthService(
		authRepository,
		passwordHasher,
		emailSender,
		nil,
		nil,
		24*time.Hour,
		12*time.Hour,
		time.Hour,
		24*time.Hour,
		10*time.Minute,
	)

	requestValidator := appvalidator.New()
	authHandler := handler.NewAuthHandler(
		authService,
		requestValidator,
		handler.SessionCookieConfig{
			Name:     "kickoutchi_session",
			Secure:   false,
			SameSite: "lax",
			TTL:      24 * time.Hour,
		},
		normalizedOptions.AllowedOrigin,
		10*time.Minute,
	)

	requireAuth := appmiddleware.RequireAuth(authService, appmiddleware.SessionCookieConfig{
		Name:     "kickoutchi_session",
		Secure:   false,
		SameSite: "lax",
		TTL:      24 * time.Hour,
	})

	csrfProtection := appmiddleware.CSRFOriginCheck(appmiddleware.CSRFConfig{
		AllowedOrigins: []string{normalizedOptions.AllowedOrigin},
	})

	authIPRateLimit := appmiddleware.RateLimitByIP(appmiddleware.NewKeyRateLimiter(
		normalizedOptions.AuthIPRateLimitRequests,
		normalizedOptions.AuthIPRateLimitWindow,
		normalizedOptions.AuthIPRateLimitBurst,
	))

	authAccountRateLimit := appmiddleware.RateLimitByJSONField(appmiddleware.NewKeyRateLimiter(
		normalizedOptions.AuthAccountRateLimitRequests,
		normalizedOptions.AuthAccountRateLimitWindow,
		normalizedOptions.AuthAccountRateLimitBurst,
	), "email")

	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))

	httpHandler := router.New(router.Dependencies{
		Logger:               logger,
		AuthHandler:          authHandler,
		AuthRequired:         requireAuth,
		CSRFProtection:       csrfProtection,
		AuthIPRateLimit:      authIPRateLimit,
		AuthAccountRateLimit: authAccountRateLimit,
	})

	httpServer := httptest.NewServer(httpHandler)
	t.Cleanup(httpServer.Close)

	return &IntegrationApp{
		BaseURL:        httpServer.URL,
		AllowedOrigin:  normalizedOptions.AllowedOrigin,
		EmailSender:    emailSender,
		AuthRepository: authRepository,
		AuthService:    authService,
		server:         httpServer,
	}
}

func (a *IntegrationApp) NewCookieClient(t *testing.T) *http.Client {
	t.Helper()

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("create cookie jar: %v", err)
	}

	return &http.Client{
		Jar:     jar,
		Timeout: 15 * time.Second,
	}
}

func NewCapturingAuthEmailSender() *CapturingAuthEmailSender {
	return &CapturingAuthEmailSender{
		verificationTokens:  make(map[string]string),
		passwordResetTokens: make(map[string]string),
	}
}

func (s *CapturingAuthEmailSender) SendVerificationEmail(_ context.Context, toEmail, _ string, token string) error {
	normalizedEmail := strings.ToLower(strings.TrimSpace(toEmail))

	s.mu.Lock()
	defer s.mu.Unlock()

	s.verificationTokens[normalizedEmail] = strings.TrimSpace(token)

	return nil
}

func (s *CapturingAuthEmailSender) SendPasswordResetEmail(_ context.Context, toEmail, _ string, token string) error {
	normalizedEmail := strings.ToLower(strings.TrimSpace(toEmail))

	s.mu.Lock()
	defer s.mu.Unlock()

	s.passwordResetTokens[normalizedEmail] = strings.TrimSpace(token)

	return nil
}

func (s *CapturingAuthEmailSender) VerificationToken(email string) (string, bool) {
	normalizedEmail := strings.ToLower(strings.TrimSpace(email))

	s.mu.Lock()
	defer s.mu.Unlock()

	token, ok := s.verificationTokens[normalizedEmail]
	return token, ok
}

func (s *CapturingAuthEmailSender) PasswordResetToken(email string) (string, bool) {
	normalizedEmail := strings.ToLower(strings.TrimSpace(email))

	s.mu.Lock()
	defer s.mu.Unlock()

	token, ok := s.passwordResetTokens[normalizedEmail]
	return token, ok
}

func (o IntegrationAppOptions) withDefaults() IntegrationAppOptions {
	if strings.TrimSpace(o.AllowedOrigin) == "" {
		o.AllowedOrigin = defaultAllowedOrigin
	}

	if o.AuthIPRateLimitRequests <= 0 {
		o.AuthIPRateLimitRequests = 1000
	}

	if o.AuthIPRateLimitWindow <= 0 {
		o.AuthIPRateLimitWindow = time.Minute
	}

	if o.AuthIPRateLimitBurst <= 0 {
		o.AuthIPRateLimitBurst = o.AuthIPRateLimitRequests
	}

	if o.AuthAccountRateLimitRequests <= 0 {
		o.AuthAccountRateLimitRequests = 1000
	}

	if o.AuthAccountRateLimitWindow <= 0 {
		o.AuthAccountRateLimitWindow = time.Minute
	}

	if o.AuthAccountRateLimitBurst <= 0 {
		o.AuthAccountRateLimitBurst = o.AuthAccountRateLimitRequests
	}

	return o
}
