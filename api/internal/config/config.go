package config

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	AppEnv   string
	LogLevel string
	HTTP     HTTPConfig
	Database DatabaseConfig
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

func Load() (Config, error) {
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

	cfg := Config{
		AppEnv:   strings.TrimSpace(getEnv("APP_ENV", "development")),
		LogLevel: strings.ToLower(strings.TrimSpace(getEnv("LOG_LEVEL", "info"))),
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

	if cfg.Database.URL == "" {
		return Config{}, errors.New("config: DATABASE_URL is required")
	}

	if err := validateLogLevel(cfg.LogLevel); err != nil {
		return Config{}, err
	}

	if err := validatePort(cfg.HTTP.Port); err != nil {
		return Config{}, err
	}

	if cfg.Database.MinConns > cfg.Database.MaxConns {
		return Config{}, errors.New("config: DB_MIN_CONNS cannot be greater than DB_MAX_CONNS")
	}

	return cfg, nil
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
