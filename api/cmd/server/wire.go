package main

import (
	"context"
	"fmt"

	"github.com/katsutoo/kickoutchi/api/internal/config"
	"github.com/katsutoo/kickoutchi/api/internal/database"
)

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
