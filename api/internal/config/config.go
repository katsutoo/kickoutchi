package config

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/katsutoo/kickoutchi/api/internal/origin"
)

type Config struct {
	AppEnv     string
	LogLevel   string
	WebBaseURL string
	HTTP       HTTPConfig
	Session    SessionConfig
	Auth       AuthConfig
	Security   SecurityConfig
	Resend     ResendConfig
	OAuth      OAuthConfig
	R2         R2Config
	Argon2     Argon2Config
	Database   DatabaseConfig
}

type HTTPConfig struct {
	Host              string
	Port              string
	ReadHeaderTimeout time.Duration
	ReadTimeout       time.Duration
	WriteTimeout      time.Duration
	IdleTimeout       time.Duration
	ReadyTimeout      time.Duration
	ShutdownTimeout   time.Duration
}

type DatabaseConfig struct {
	URL               string
	MaxConns          int32
	MinConns          int32
	MaxConnLifetime   time.Duration
	MaxConnIdleTime   time.Duration
	HealthCheckPeriod time.Duration
	ConnectTimeout    time.Duration
}

type SessionConfig struct {
	CookieName     string
	CookieDomain   string
	CookieSecure   bool
	CookieSameSite string
	TTL            time.Duration
	RefreshWindow  time.Duration
}

type Argon2Config struct {
	Memory     uint32
	Time       uint32
	Threads    uint8
	KeyLength  uint32
	SaltLength uint32
}

type AuthConfig struct {
	PasswordResetTokenTTL     time.Duration
	EmailVerificationTokenTTL time.Duration
	OAuthStateTTL             time.Duration
}

type SecurityConfig struct {
	CSRFAllowedOrigins           []string
	TrustedProxyCIDRs            []string
	AuthIPRateLimitRequests      int
	AuthIPRateLimitWindow        time.Duration
	AuthIPRateLimitBurst         int
	AuthAccountRateLimitRequests int
	AuthAccountRateLimitWindow   time.Duration
	AuthAccountRateLimitBurst    int
	ResendVerificationRequests   int
	ResendVerificationWindow     time.Duration
	ResendVerificationBurst      int
}

type ResendConfig struct {
	APIKey     string
	FromEmail  string
	APIBaseURL string
}

type OAuthConfig struct {
	GitHubClientID     string
	GitHubClientSecret string
	GitHubRedirectURL  string
}

type R2Config struct {
	AccountID       string
	Bucket          string
	AccessKeyID     string
	SecretAccessKey string
	Region          string
	SignedUploadTTL time.Duration
	SignedReadTTL   time.Duration
}

func Load() (Config, error) {
	appEnv := strings.TrimSpace(getEnv("APP_ENV", "development"))

	readHeaderTimeout, err := durationFromEnv("HTTP_READ_HEADER_TIMEOUT", 5*time.Second)
	if err != nil {
		return Config{}, err
	}

	readTimeout, err := durationFromEnv("HTTP_READ_TIMEOUT", 15*time.Second)
	if err != nil {
		return Config{}, err
	}

	writeTimeout, err := durationFromEnv("HTTP_WRITE_TIMEOUT", 15*time.Second)
	if err != nil {
		return Config{}, err
	}

	idleTimeout, err := durationFromEnv("HTTP_IDLE_TIMEOUT", 60*time.Second)
	if err != nil {
		return Config{}, err
	}

	readyTimeout, err := durationFromEnv("HTTP_READY_TIMEOUT", 2*time.Second)
	if err != nil {
		return Config{}, err
	}

	shutdownTimeout, err := durationFromEnv("HTTP_SHUTDOWN_TIMEOUT", 10*time.Second)
	if err != nil {
		return Config{}, err
	}

	maxConns, err := int32FromEnv("DB_MAX_CONNS", 10)
	if err != nil {
		return Config{}, err
	}

	minConns, err := int32FromEnv("DB_MIN_CONNS", 0)
	if err != nil {
		return Config{}, err
	}

	maxConnLifetime, err := durationFromEnv("DB_MAX_CONN_LIFETIME", 30*time.Minute)
	if err != nil {
		return Config{}, err
	}

	maxConnIdleTime, err := durationFromEnv("DB_MAX_CONN_IDLE_TIME", 5*time.Minute)
	if err != nil {
		return Config{}, err
	}

	healthCheckPeriod, err := durationFromEnv("DB_HEALTH_CHECK_PERIOD", 30*time.Second)
	if err != nil {
		return Config{}, err
	}

	connectTimeout, err := durationFromEnv("DB_CONNECT_TIMEOUT", 5*time.Second)
	if err != nil {
		return Config{}, err
	}

	passwordResetTokenTTL, err := durationFromEnv("PASSWORD_RESET_TOKEN_TTL", time.Hour)
	if err != nil {
		return Config{}, err
	}

	emailVerificationTokenTTL, err := durationFromEnv("EMAIL_VERIFICATION_TOKEN_TTL", 24*time.Hour)
	if err != nil {
		return Config{}, err
	}

	oauthStateTTL, err := durationFromEnv("OAUTH_STATE_TTL", 10*time.Minute)
	if err != nil {
		return Config{}, err
	}

	sessionTTL, err := durationFromEnv("SESSION_TTL", 30*24*time.Hour)
	if err != nil {
		return Config{}, err
	}

	sessionRefreshWindow, err := durationFromEnv("SESSION_REFRESH_WINDOW", 24*time.Hour)
	if err != nil {
		return Config{}, err
	}

	authIPRateLimitRequests, err := intFromEnv("AUTH_IP_RATE_LIMIT_REQUESTS", 30)
	if err != nil {
		return Config{}, err
	}

	authIPRateLimitWindow, err := durationFromEnv("AUTH_IP_RATE_LIMIT_WINDOW", time.Minute)
	if err != nil {
		return Config{}, err
	}

	authIPRateLimitBurst, err := intFromEnv("AUTH_IP_RATE_LIMIT_BURST", 10)
	if err != nil {
		return Config{}, err
	}

	authAccountRateLimitRequests, err := intFromEnv("AUTH_ACCOUNT_RATE_LIMIT_REQUESTS", 5)
	if err != nil {
		return Config{}, err
	}

	authAccountRateLimitWindow, err := durationFromEnv("AUTH_ACCOUNT_RATE_LIMIT_WINDOW", 5*time.Minute)
	if err != nil {
		return Config{}, err
	}

	authAccountRateLimitBurst, err := intFromEnv("AUTH_ACCOUNT_RATE_LIMIT_BURST", 3)
	if err != nil {
		return Config{}, err
	}

	resendVerificationRequests, err := intFromEnv("AUTH_RESEND_VERIFICATION_RATE_LIMIT_REQUESTS", 1)
	if err != nil {
		return Config{}, err
	}

	resendVerificationWindow, err := durationFromEnv("AUTH_RESEND_VERIFICATION_RATE_LIMIT_WINDOW", time.Minute)
	if err != nil {
		return Config{}, err
	}

	resendVerificationBurst, err := intFromEnv("AUTH_RESEND_VERIFICATION_RATE_LIMIT_BURST", 1)
	if err != nil {
		return Config{}, err
	}

	webBaseURL := strings.TrimSpace(getEnv("WEB_BASE_URL", "http://localhost:5173"))
	csrfAllowedOriginsRaw := strings.TrimSpace(os.Getenv("CSRF_ALLOWED_ORIGINS"))
	csrfAllowedOrigins, err := originsFromEnv(csrfAllowedOriginsRaw, webBaseURL)
	if err != nil {
		return Config{}, err
	}

	trustedProxyCIDRs, err := cidrsFromEnv(strings.TrimSpace(os.Getenv("TRUSTED_PROXY_CIDRS")))
	if err != nil {
		return Config{}, err
	}

	resendAPIKey := strings.TrimSpace(os.Getenv("RESEND_API_KEY"))
	resendFromEmail := strings.TrimSpace(os.Getenv("RESEND_FROM_EMAIL"))
	resendAPIBaseURL := strings.TrimSpace(getEnv("RESEND_API_BASE_URL", "https://api.resend.com"))

	githubClientID := strings.TrimSpace(os.Getenv("GITHUB_CLIENT_ID"))
	githubClientSecret := strings.TrimSpace(os.Getenv("GITHUB_CLIENT_SECRET"))
	githubRedirectURL := strings.TrimSpace(os.Getenv("GITHUB_REDIRECT_URL"))

	r2SignedUploadTTL, err := durationFromEnv("R2_SIGNED_UPLOAD_TTL", 10*time.Minute)
	if err != nil {
		return Config{}, err
	}

	r2SignedReadTTL, err := durationFromEnv("R2_SIGNED_READ_TTL", 10*time.Minute)
	if err != nil {
		return Config{}, err
	}

	r2AccountID := strings.TrimSpace(os.Getenv("R2_ACCOUNT_ID"))
	r2Bucket := strings.TrimSpace(os.Getenv("R2_BUCKET"))
	r2AccessKeyID := strings.TrimSpace(os.Getenv("R2_ACCESS_KEY_ID"))
	r2SecretAccessKey := strings.TrimSpace(os.Getenv("R2_SECRET_ACCESS_KEY"))
	r2Region := strings.TrimSpace(getEnv("R2_REGION", "auto"))

	cookieSecureDefault := strings.EqualFold(appEnv, "production")
	cookieSecure, err := boolFromEnv("COOKIE_SECURE", cookieSecureDefault)
	if err != nil {
		return Config{}, err
	}

	argon2Memory, err := uint32FromEnv("ARGON2_MEMORY", 19456)
	if err != nil {
		return Config{}, err
	}

	argon2Time, err := uint32FromEnv("ARGON2_TIME", 2)
	if err != nil {
		return Config{}, err
	}

	argon2Threads, err := uint8FromEnv("ARGON2_THREADS", 1)
	if err != nil {
		return Config{}, err
	}

	argon2KeyLength, err := uint32FromEnv("ARGON2_KEY_LENGTH", 32)
	if err != nil {
		return Config{}, err
	}

	argon2SaltLength, err := uint32FromEnv("ARGON2_SALT_LENGTH", 16)
	if err != nil {
		return Config{}, err
	}

	cfg := Config{
		AppEnv:     appEnv,
		LogLevel:   strings.ToLower(strings.TrimSpace(getEnv("LOG_LEVEL", "info"))),
		WebBaseURL: webBaseURL,
		HTTP: HTTPConfig{
			Host:              strings.TrimSpace(getEnv("HOST", "0.0.0.0")),
			Port:              strings.TrimSpace(getEnv("PORT", "8080")),
			ReadHeaderTimeout: readHeaderTimeout,
			ReadTimeout:       readTimeout,
			WriteTimeout:      writeTimeout,
			IdleTimeout:       idleTimeout,
			ReadyTimeout:      readyTimeout,
			ShutdownTimeout:   shutdownTimeout,
		},
		Session: SessionConfig{
			CookieName:     strings.TrimSpace(getEnv("SESSION_COOKIE_NAME", "kickoutchi_session")),
			CookieDomain:   strings.TrimSpace(os.Getenv("COOKIE_DOMAIN")),
			CookieSecure:   cookieSecure,
			CookieSameSite: strings.ToLower(strings.TrimSpace(getEnv("COOKIE_SAME_SITE", "lax"))),
			TTL:            sessionTTL,
			RefreshWindow:  sessionRefreshWindow,
		},
		Auth: AuthConfig{
			PasswordResetTokenTTL:     passwordResetTokenTTL,
			EmailVerificationTokenTTL: emailVerificationTokenTTL,
			OAuthStateTTL:             oauthStateTTL,
		},
		Security: SecurityConfig{
			CSRFAllowedOrigins:           csrfAllowedOrigins,
			TrustedProxyCIDRs:            trustedProxyCIDRs,
			AuthIPRateLimitRequests:      authIPRateLimitRequests,
			AuthIPRateLimitWindow:        authIPRateLimitWindow,
			AuthIPRateLimitBurst:         authIPRateLimitBurst,
			AuthAccountRateLimitRequests: authAccountRateLimitRequests,
			AuthAccountRateLimitWindow:   authAccountRateLimitWindow,
			AuthAccountRateLimitBurst:    authAccountRateLimitBurst,
			ResendVerificationRequests:   resendVerificationRequests,
			ResendVerificationWindow:     resendVerificationWindow,
			ResendVerificationBurst:      resendVerificationBurst,
		},
		Resend: ResendConfig{
			APIKey:     resendAPIKey,
			FromEmail:  resendFromEmail,
			APIBaseURL: resendAPIBaseURL,
		},
		OAuth: OAuthConfig{
			GitHubClientID:     githubClientID,
			GitHubClientSecret: githubClientSecret,
			GitHubRedirectURL:  githubRedirectURL,
		},
		R2: R2Config{
			AccountID:       r2AccountID,
			Bucket:          r2Bucket,
			AccessKeyID:     r2AccessKeyID,
			SecretAccessKey: r2SecretAccessKey,
			Region:          r2Region,
			SignedUploadTTL: r2SignedUploadTTL,
			SignedReadTTL:   r2SignedReadTTL,
		},
		Argon2: Argon2Config{
			Memory:     argon2Memory,
			Time:       argon2Time,
			Threads:    argon2Threads,
			KeyLength:  argon2KeyLength,
			SaltLength: argon2SaltLength,
		},
		Database: DatabaseConfig{
			URL:               strings.TrimSpace(os.Getenv("DATABASE_URL")),
			MaxConns:          maxConns,
			MinConns:          minConns,
			MaxConnLifetime:   maxConnLifetime,
			MaxConnIdleTime:   maxConnIdleTime,
			HealthCheckPeriod: healthCheckPeriod,
			ConnectTimeout:    connectTimeout,
		},
	}

	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}

	return cfg, nil
}

func (c Config) Validate() error {
	if c.Database.URL == "" {
		return errors.New("config: DATABASE_URL is required")
	}

	if err := validateAbsoluteURL("WEB_BASE_URL", c.WebBaseURL); err != nil {
		return err
	}

	if err := validateLogLevel(c.LogLevel); err != nil {
		return err
	}

	if err := validatePort(c.HTTP.Port); err != nil {
		return err
	}

	if c.Session.CookieName == "" {
		return errors.New("config: SESSION_COOKIE_NAME is required")
	}

	if c.Session.RefreshWindow > c.Session.TTL {
		return errors.New("config: SESSION_REFRESH_WINDOW cannot be greater than SESSION_TTL")
	}

	if err := validateSameSite(c.Session.CookieSameSite); err != nil {
		return err
	}

	if c.Session.CookieSameSite == "none" && !c.Session.CookieSecure {
		return errors.New("config: COOKIE_SECURE must be true when COOKIE_SAME_SITE is none")
	}

	if strings.EqualFold(c.AppEnv, "production") && !c.Session.CookieSecure {
		return errors.New("config: COOKIE_SECURE must be true in production")
	}

	if c.Database.MinConns > c.Database.MaxConns {
		return errors.New("config: DB_MIN_CONNS cannot be greater than DB_MAX_CONNS")
	}

	if strings.EqualFold(c.AppEnv, "production") && c.Resend.APIKey == "" {
		return errors.New("config: RESEND_API_KEY and RESEND_FROM_EMAIL are required in production")
	}

	if c.Resend.APIKey != "" && c.Resend.FromEmail == "" {
		return errors.New("config: RESEND_FROM_EMAIL is required when RESEND_API_KEY is set")
	}

	if c.Resend.APIKey == "" && c.Resend.FromEmail != "" {
		return errors.New("config: RESEND_API_KEY is required when RESEND_FROM_EMAIL is set")
	}

	if c.Resend.APIBaseURL == "" {
		return errors.New("config: RESEND_API_BASE_URL is required")
	}

	if err := validateAbsoluteURL("RESEND_API_BASE_URL", c.Resend.APIBaseURL); err != nil {
		return err
	}

	if err := validateGitHubOAuthConfig(c.OAuth); err != nil {
		return err
	}

	if err := validateR2Config(c.R2); err != nil {
		return err
	}

	return nil
}

func (c Config) HTTPAddr() string {
	return net.JoinHostPort(c.HTTP.Host, c.HTTP.Port)
}

func getEnv(key, fallback string) string {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}

	return value
}

func durationFromEnv(key string, fallback time.Duration) (time.Duration, error) {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback, nil
	}

	value, err := time.ParseDuration(raw)
	if err != nil {
		return 0, fmt.Errorf("config: invalid duration for %s: %w", key, err)
	}

	if value <= 0 {
		return 0, fmt.Errorf("config: %s must be greater than zero", key)
	}

	return value, nil
}

func int32FromEnv(key string, fallback int32) (int32, error) {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback, nil
	}

	value, err := strconv.ParseInt(raw, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("config: invalid integer for %s: %w", key, err)
	}

	if value < 0 {
		return 0, fmt.Errorf("config: %s cannot be negative", key)
	}

	return int32(value), nil
}

func intFromEnv(key string, fallback int) (int, error) {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback, nil
	}

	value, err := strconv.Atoi(raw)
	if err != nil {
		return 0, fmt.Errorf("config: invalid integer for %s: %w", key, err)
	}

	if value <= 0 {
		return 0, fmt.Errorf("config: %s must be greater than zero", key)
	}

	return value, nil
}

func uint32FromEnv(key string, fallback uint32) (uint32, error) {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback, nil
	}

	value, err := strconv.ParseUint(raw, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("config: invalid unsigned integer for %s: %w", key, err)
	}

	if value == 0 {
		return 0, fmt.Errorf("config: %s must be greater than zero", key)
	}

	return uint32(value), nil
}

func uint8FromEnv(key string, fallback uint8) (uint8, error) {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback, nil
	}

	value, err := strconv.ParseUint(raw, 10, 8)
	if err != nil {
		return 0, fmt.Errorf("config: invalid unsigned integer for %s: %w", key, err)
	}

	if value == 0 {
		return 0, fmt.Errorf("config: %s must be greater than zero", key)
	}

	return uint8(value), nil
}

func boolFromEnv(key string, fallback bool) (bool, error) {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback, nil
	}

	value, err := strconv.ParseBool(raw)
	if err != nil {
		return false, fmt.Errorf("config: invalid boolean for %s: %w", key, err)
	}

	return value, nil
}

func originsFromEnv(raw, fallbackOrigin string) ([]string, error) {
	var values []string
	if strings.TrimSpace(raw) == "" {
		values = []string{fallbackOrigin}
	} else {
		parts := strings.Split(raw, ",")
		values = make([]string, 0, len(parts))
		for _, part := range parts {
			trimmed := strings.TrimSpace(part)
			if trimmed == "" {
				continue
			}
			values = append(values, trimmed)
		}
	}

	if len(values) == 0 {
		return nil, errors.New("config: CSRF_ALLOWED_ORIGINS cannot be empty")
	}

	normalized := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		normalizedOrigin, err := origin.Normalize(value)
		if err != nil {
			return nil, fmt.Errorf("config: invalid CSRF origin %q: %w", value, err)
		}

		if _, exists := seen[normalizedOrigin]; exists {
			continue
		}

		seen[normalizedOrigin] = struct{}{}
		normalized = append(normalized, normalizedOrigin)
	}

	return normalized, nil
}

func cidrsFromEnv(raw string) ([]string, error) {
	if raw == "" {
		return nil, nil
	}

	parts := strings.Split(raw, ",")
	normalized := make([]string, 0, len(parts))
	seen := make(map[string]struct{}, len(parts))
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed == "" {
			continue
		}

		if ip := net.ParseIP(trimmed); ip != nil {
			if ip.To4() != nil {
				trimmed += "/32"
			} else {
				trimmed += "/128"
			}
		}

		if _, _, err := net.ParseCIDR(trimmed); err != nil {
			return nil, fmt.Errorf("config: invalid TRUSTED_PROXY_CIDRS entry %q: %w", part, err)
		}

		if _, exists := seen[trimmed]; exists {
			continue
		}

		seen[trimmed] = struct{}{}
		normalized = append(normalized, trimmed)
	}

	return normalized, nil
}

func validatePort(port string) error {
	value, err := strconv.Atoi(port)
	if err != nil {
		return fmt.Errorf("config: PORT must be numeric: %w", err)
	}

	if value < 1 || value > 65535 {
		return errors.New("config: PORT must be between 1 and 65535")
	}

	return nil
}

func validateLogLevel(level string) error {
	valid := map[string]struct{}{
		"debug": {},
		"info":  {},
		"warn":  {},
		"error": {},
	}

	if _, ok := valid[level]; ok {
		return nil
	}

	return errors.New("config: LOG_LEVEL must be one of debug, info, warn, error")
}

func validateSameSite(value string) error {
	valid := map[string]struct{}{
		"lax":    {},
		"strict": {},
		"none":   {},
	}

	if _, ok := valid[value]; ok {
		return nil
	}

	return errors.New("config: COOKIE_SAME_SITE must be one of lax, strict, none")
}

func validateAbsoluteURL(key, value string) error {
	parsed, err := url.Parse(value)
	if err != nil {
		return fmt.Errorf("config: invalid %s URL: %w", key, err)
	}

	if parsed.Scheme == "" || parsed.Host == "" {
		return fmt.Errorf("config: %s must be an absolute URL", key)
	}

	return nil
}

func validateGitHubOAuthConfig(cfg OAuthConfig) error {
	fieldsSet := 0
	if cfg.GitHubClientID != "" {
		fieldsSet++
	}
	if cfg.GitHubClientSecret != "" {
		fieldsSet++
	}
	if cfg.GitHubRedirectURL != "" {
		fieldsSet++
	}

	if fieldsSet == 0 {
		return nil
	}

	if fieldsSet != 3 {
		return errors.New("config: GITHUB_CLIENT_ID, GITHUB_CLIENT_SECRET, and GITHUB_REDIRECT_URL must all be set together")
	}

	if err := validateAbsoluteURL("GITHUB_REDIRECT_URL", cfg.GitHubRedirectURL); err != nil {
		return err
	}

	return nil
}

func validateR2Config(cfg R2Config) error {
	fieldsSet := 0
	if cfg.AccountID != "" {
		fieldsSet++
	}
	if cfg.Bucket != "" {
		fieldsSet++
	}
	if cfg.AccessKeyID != "" {
		fieldsSet++
	}
	if cfg.SecretAccessKey != "" {
		fieldsSet++
	}

	if fieldsSet == 0 {
		return nil
	}

	if fieldsSet != 4 {
		return errors.New("config: R2_ACCOUNT_ID, R2_BUCKET, R2_ACCESS_KEY_ID, and R2_SECRET_ACCESS_KEY must all be set together")
	}

	if cfg.Region == "" {
		return errors.New("config: R2_REGION is required when R2 is enabled")
	}

	return nil
}
