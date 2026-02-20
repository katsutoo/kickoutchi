//go:build integration
// +build integration

package integration

import (
	"net/http"
	"testing"
	"time"

	"github.com/katsutoo/kickoutchi/api/test/testutil"
)

func TestAuthAccountRateLimitIntegration(t *testing.T) {
	app := testutil.NewIntegrationApp(t, testutil.IntegrationAppOptions{
		AuthIPRateLimitRequests:      100,
		AuthIPRateLimitWindow:        time.Hour,
		AuthIPRateLimitBurst:         100,
		AuthAccountRateLimitRequests: 1,
		AuthAccountRateLimitWindow:   time.Hour,
		AuthAccountRateLimitBurst:    1,
	})

	client := app.NewCookieClient(t)

	status, body, _ := doJSONRequest(
		t,
		client,
		http.MethodPost,
		app.BaseURL+"/v1/auth/login",
		map[string]string{"email": "limited@example.com", "password": "WrongPass1!"},
		nil,
	)
	requireStatus(t, status, http.StatusUnauthorized, body)

	status, body, headers := doJSONRequest(
		t,
		client,
		http.MethodPost,
		app.BaseURL+"/v1/auth/login",
		map[string]string{"email": "limited@example.com", "password": "WrongPass1!"},
		nil,
	)
	requireStatus(t, status, http.StatusTooManyRequests, body)

	if retryAfter := headers.Get("Retry-After"); retryAfter == "" {
		t.Fatalf("expected Retry-After header when account rate limit is exceeded")
	}

	status, body, _ = doJSONRequest(
		t,
		client,
		http.MethodPost,
		app.BaseURL+"/v1/auth/login",
		map[string]string{"email": "other@example.com", "password": "WrongPass1!"},
		nil,
	)
	requireStatus(t, status, http.StatusUnauthorized, body)
}

func TestAuthIPRateLimitIntegration(t *testing.T) {
	app := testutil.NewIntegrationApp(t, testutil.IntegrationAppOptions{
		AuthIPRateLimitRequests:      1,
		AuthIPRateLimitWindow:        time.Hour,
		AuthIPRateLimitBurst:         1,
		AuthAccountRateLimitRequests: 100,
		AuthAccountRateLimitWindow:   time.Hour,
		AuthAccountRateLimitBurst:    100,
	})

	client := app.NewCookieClient(t)

	status, body, _ := doJSONRequest(
		t,
		client,
		http.MethodPost,
		app.BaseURL+"/v1/auth/forgot-password",
		map[string]string{"email": uniqueEmail("rate_ip_first")},
		nil,
	)
	requireStatus(t, status, http.StatusOK, body)

	status, body, headers := doJSONRequest(
		t,
		client,
		http.MethodPost,
		app.BaseURL+"/v1/auth/forgot-password",
		map[string]string{"email": uniqueEmail("rate_ip_second")},
		nil,
	)
	requireStatus(t, status, http.StatusTooManyRequests, body)

	if retryAfter := headers.Get("Retry-After"); retryAfter == "" {
		t.Fatalf("expected Retry-After header when IP rate limit is exceeded")
	}
}
