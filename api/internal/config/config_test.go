package config

import (
	"strings"
	"testing"
)

func TestLoadRequiresResendInProduction(t *testing.T) {
	t.Setenv("DATABASE_URL", "postgres://kickoutchi:kickoutchi@localhost:5432/kickoutchi?sslmode=disable")
	t.Setenv("APP_ENV", "production")
	t.Setenv("RESEND_API_KEY", "")
	t.Setenv("RESEND_FROM_EMAIL", "")

	_, err := Load()
	if err == nil {
		t.Fatalf("expected production config to require resend configuration")
	}

	if !strings.Contains(err.Error(), "RESEND_API_KEY") {
		t.Fatalf("unexpected production resend validation error: %v", err)
	}
}

func TestLoadNormalizesTrustedProxyCIDRs(t *testing.T) {
	t.Setenv("DATABASE_URL", "postgres://kickoutchi:kickoutchi@localhost:5432/kickoutchi?sslmode=disable")
	t.Setenv("APP_ENV", "development")
	t.Setenv("TRUSTED_PROXY_CIDRS", "10.0.0.0/8, 203.0.113.10")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("load config returned error: %v", err)
	}

	if len(cfg.Security.TrustedProxyCIDRs) != 2 {
		t.Fatalf("unexpected trusted proxy cidr count: %d", len(cfg.Security.TrustedProxyCIDRs))
	}

	if cfg.Security.TrustedProxyCIDRs[1] != "203.0.113.10/32" {
		t.Fatalf("unexpected normalized trusted proxy cidr: %q", cfg.Security.TrustedProxyCIDRs[1])
	}
}
