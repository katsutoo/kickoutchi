package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/katsutoo/kickoutchi/api/internal/auth"
	"github.com/katsutoo/kickoutchi/api/internal/config"
	"github.com/katsutoo/kickoutchi/api/internal/database"
	"github.com/katsutoo/kickoutchi/api/internal/repository"
	"github.com/katsutoo/kickoutchi/api/internal/seed"
)

const seedCommandTimeout = 30 * time.Second

func main() {
	if err := run(); err != nil {
		slog.Error("seed_failed", slog.Any("err", err))
		os.Exit(1)
	}
}

func run() error {
	if err := config.LoadDotEnv(".env"); err != nil {
		return fmt.Errorf("load .env: %w", err)
	}

	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	logger := newLogger(cfg.LogLevel)
	slog.SetDefault(logger)

	allowNonDev, err := boolFromEnv("SEED_ALLOW_NON_DEV", false)
	if err != nil {
		return err
	}

	if !strings.EqualFold(cfg.AppEnv, "development") && !allowNonDev {
		return errors.New("seed command is restricted to development; set SEED_ALLOW_NON_DEV=true to override")
	}

	seedPassword := strings.TrimSpace(os.Getenv("SEED_DEFAULT_PASSWORD"))
	if seedPassword == "" {
		return errors.New("SEED_DEFAULT_PASSWORD is required")
	}

	ctx, cancel := context.WithTimeout(context.Background(), seedCommandTimeout)
	defer cancel()

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
		return fmt.Errorf("create database pool: %w", err)
	}
	defer db.Close()

	authRepository := repository.NewAuthRepository(db)
	passwordHasher := auth.NewArgon2Hasher(auth.Argon2Params{
		Memory:     cfg.Argon2.Memory,
		Time:       cfg.Argon2.Time,
		Threads:    cfg.Argon2.Threads,
		KeyLength:  cfg.Argon2.KeyLength,
		SaltLength: cfg.Argon2.SaltLength,
	})

	result, err := seed.SeedUsers(ctx, authRepository, passwordHasher, seedPassword, seed.DefaultUsers(), logger)
	if err != nil {
		return fmt.Errorf("seed default users: %w", err)
	}

	logger.Info(
		"seed_completed",
		slog.Int("created", result.Created),
		slog.Int("existing", result.Existing),
		slog.Int("total", result.Created+result.Existing),
	)

	logger.Info(
		"seed_credentials",
		slog.String("password_env", "SEED_DEFAULT_PASSWORD"),
		slog.String("user_email", "local-user@kickoutchi.dev"),
		slog.String("admin_email", "local-admin@kickoutchi.dev"),
	)

	return nil
}

func boolFromEnv(key string, fallback bool) (bool, error) {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback, nil
	}

	value, err := strconv.ParseBool(raw)
	if err != nil {
		return false, fmt.Errorf("invalid boolean for %s: %w", key, err)
	}

	return value, nil
}

func newLogger(level string) *slog.Logger {
	var slogLevel slog.Level

	switch strings.ToLower(strings.TrimSpace(level)) {
	case "debug":
		slogLevel = slog.LevelDebug
	case "warn":
		slogLevel = slog.LevelWarn
	case "error":
		slogLevel = slog.LevelError
	default:
		slogLevel = slog.LevelInfo
	}

	handler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slogLevel})
	return slog.New(handler)
}
