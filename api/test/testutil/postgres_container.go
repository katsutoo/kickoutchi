package testutil

import (
	"context"
	"database/sql"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/katsutoo/kickoutchi/api/internal/database"
)

const (
	testDBName       = "kickoutchi_test"
	testDBUser       = "kickoutchi"
	testDBPassword   = "kickoutchi"
	containerTimeout = 90 * time.Second
)

func NewDatabase(t *testing.T) *database.DB {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), containerTimeout)
	defer cancel()

	pgContainer, err := postgres.Run(
		ctx,
		"postgres:16-alpine",
		postgres.WithDatabase(testDBName),
		postgres.WithUsername(testDBUser),
		postgres.WithPassword(testDBPassword),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").WithOccurrence(2).WithStartupTimeout(containerTimeout),
		),
	)
	if err != nil {
		t.Skipf("integration test requires docker/testcontainers: %v", err)
	}

	t.Cleanup(func() {
		_ = pgContainer.Terminate(context.Background())
	})

	connectionString, err := pgContainer.ConnectionString(context.Background(), "sslmode=disable")
	if err != nil {
		t.Fatalf("build postgres connection string: %v", err)
	}

	applyMigrations(t, connectionString)

	db, err := database.New(context.Background(), database.Config{
		URL:               connectionString,
		MaxConns:          16,
		MinConns:          0,
		MaxConnLifetime:   5 * time.Minute,
		MaxConnIdleTime:   2 * time.Minute,
		HealthCheckPeriod: time.Minute,
		ConnectTimeout:    10 * time.Second,
	})
	if err != nil {
		t.Fatalf("create test database pool: %v", err)
	}

	t.Cleanup(func() {
		db.Close()
	})

	return db
}

func applyMigrations(t *testing.T, connectionString string) {
	t.Helper()

	sqlDB, err := sql.Open("pgx", connectionString)
	if err != nil {
		t.Fatalf("open sql database for migrations: %v", err)
	}
	t.Cleanup(func() {
		_ = sqlDB.Close()
	})

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := sqlDB.PingContext(ctx); err != nil {
		t.Fatalf("ping sql database before migrations: %v", err)
	}

	if err := goose.SetDialect("postgres"); err != nil {
		t.Fatalf("set goose dialect: %v", err)
	}

	if err := goose.UpContext(ctx, sqlDB, migrationDir(t)); err != nil {
		t.Fatalf("run goose migrations: %v", err)
	}
}

func migrationDir(t *testing.T) string {
	t.Helper()

	_, filePath, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatalf("resolve runtime caller for migrations path")
	}

	apiRoot := filepath.Clean(filepath.Join(filepath.Dir(filePath), "..", ".."))
	return filepath.Join(apiRoot, "sql", "schema")
}
