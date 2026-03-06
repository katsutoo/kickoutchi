package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/katsutoo/kickoutchi/api/internal/config"
	"github.com/katsutoo/kickoutchi/api/internal/handler"
	"github.com/katsutoo/kickoutchi/api/internal/middleware"
	"github.com/katsutoo/kickoutchi/api/internal/router"
)

func main() {
	if err := run(); err != nil {
		slog.Error("server_start_failed", slog.Any("err", err))
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

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	db, err := newDatabase(ctx, cfg)
	if err != nil {
		return fmt.Errorf("initialize database: %w", err)
	}
	defer db.Close()

	healthHandler := handler.NewHealthHandler(db, cfg.HTTP.ReadyTimeout)
	authComponents, err := newAuthComponents(cfg, db, logger)
	if err != nil {
		return fmt.Errorf("initialize auth components: %w", err)
	}

	httpHandler := router.New(router.Dependencies{
		Logger:                logger,
		HealthHandler:         healthHandler,
		AuthHandler:           authComponents.Handler,
		RealIP:                middleware.RealIP(middleware.RealIPConfig{TrustedProxyCIDRs: cfg.Security.TrustedProxyCIDRs}),
		AuthRequired:          authComponents.RequireAuth,
		CSRFProtection:        authComponents.CSRFProtection,
		AuthIPRateLimit:       authComponents.AuthIPRateLimit,
		AuthAccountRateLimit:  authComponents.AuthAccountRateLimit,
		ResendVerifyRateLimit: authComponents.ResendVerifyRateLimit,
	})

	server := &http.Server{
		Addr:              cfg.HTTPAddr(),
		Handler:           httpHandler,
		ReadHeaderTimeout: cfg.HTTP.ReadHeaderTimeout,
		ReadTimeout:       cfg.HTTP.ReadTimeout,
		WriteTimeout:      cfg.HTTP.WriteTimeout,
		IdleTimeout:       cfg.HTTP.IdleTimeout,
	}

	errCh := make(chan error, 1)

	go func() {
		logger.Info(
			"http_server_starting",
			slog.String("addr", cfg.HTTPAddr()),
			slog.String("env", cfg.AppEnv),
		)

		err := server.ListenAndServe()
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
			return
		}

		errCh <- nil
	}()

	select {
	case err := <-errCh:
		if err != nil {
			return fmt.Errorf("http server failed: %w", err)
		}
		return nil
	case <-ctx.Done():
		logger.Info("shutdown_signal_received")
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.HTTP.ShutdownTimeout)
	defer cancel()

	if err := server.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("shutdown http server: %w", err)
	}

	if err := <-errCh; err != nil {
		return fmt.Errorf("http server stop error: %w", err)
	}

	logger.Info("http_server_stopped")

	return nil
}

func newLogger(level string) *slog.Logger {
	var slogLevel slog.Level

	switch strings.ToLower(level) {
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
