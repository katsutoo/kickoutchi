//go:build integration
// +build integration

package integration

import (
	"net/http"
	"testing"

	"github.com/katsutoo/kickoutchi/api/test/testutil"
)

func TestAuthLifecycleIntegration(t *testing.T) {
	app := testutil.NewIntegrationApp(t, testutil.IntegrationAppOptions{})
	client := app.NewCookieClient(t)

	email := uniqueEmail("auth_lifecycle")
	password := "Str0ngPassw0rd!"
	displayName := uniqueDisplayName("auth_user")

	status, body, _ := doJSONRequest(
		t,
		client,
		http.MethodPost,
		app.BaseURL+"/v1/auth/register",
		map[string]string{
			"email":        email,
			"password":     password,
			"display_name": displayName,
		},
		nil,
	)
	requireStatus(t, status, http.StatusCreated, body)

	verificationToken, ok := app.EmailSender.VerificationToken(email)
	if !ok || verificationToken == "" {
		t.Fatalf("expected verification token to be captured for %s", email)
	}

	status, body, _ = doJSONRequest(
		t,
		client,
		http.MethodPost,
		app.BaseURL+"/v1/auth/verify-email",
		map[string]string{"token": verificationToken},
		nil,
	)
	requireStatus(t, status, http.StatusOK, body)

	status, body, _ = doJSONRequest(
		t,
		client,
		http.MethodPost,
		app.BaseURL+"/v1/auth/logout",
		map[string]string{},
		map[string]string{"Origin": app.AllowedOrigin},
	)
	requireStatus(t, status, http.StatusOK, body)

	status, body, _ = doJSONRequest(
		t,
		client,
		http.MethodPost,
		app.BaseURL+"/v1/auth/login",
		map[string]string{"email": email, "password": password},
		nil,
	)
	requireStatus(t, status, http.StatusOK, body)

	status, body, _ = doJSONRequest(t, client, http.MethodGet, app.BaseURL+"/v1/me", nil, nil)
	requireStatus(t, status, http.StatusOK, body)

	authResult := mustDecodeJSON[authResultEnvelope](t, body)
	if authResult.Data.User.Email != email {
		t.Fatalf("unexpected authenticated email: got=%q expected=%q", authResult.Data.User.Email, email)
	}

	if authResult.Data.User.EmailVerifiedAt == nil {
		t.Fatalf("expected email to be verified after verify-email flow")
	}

	anonymousClient := app.NewCookieClient(t)
	status, body, _ = doJSONRequest(t, anonymousClient, http.MethodGet, app.BaseURL+"/v1/me", nil, nil)
	requireStatus(t, status, http.StatusUnauthorized, body)
}

func TestPasswordResetIntegration(t *testing.T) {
	app := testutil.NewIntegrationApp(t, testutil.IntegrationAppOptions{})
	client := app.NewCookieClient(t)

	email := uniqueEmail("password_reset")
	oldPassword := "Str0ngPassw0rd!"
	newPassword := "N3wPassw0rd!"

	status, body, _ := doJSONRequest(
		t,
		client,
		http.MethodPost,
		app.BaseURL+"/v1/auth/register",
		map[string]string{
			"email":        email,
			"password":     oldPassword,
			"display_name": uniqueDisplayName("reset_user"),
		},
		nil,
	)
	requireStatus(t, status, http.StatusCreated, body)

	status, body, _ = doJSONRequest(
		t,
		client,
		http.MethodPost,
		app.BaseURL+"/v1/auth/forgot-password",
		map[string]string{"email": email},
		nil,
	)
	requireStatus(t, status, http.StatusOK, body)

	resetToken, ok := app.EmailSender.PasswordResetToken(email)
	if !ok || resetToken == "" {
		t.Fatalf("expected password reset token to be captured for %s", email)
	}

	status, body, _ = doJSONRequest(
		t,
		client,
		http.MethodPost,
		app.BaseURL+"/v1/auth/reset-password",
		map[string]string{"token": resetToken, "password": newPassword},
		nil,
	)
	requireStatus(t, status, http.StatusOK, body)

	status, body, _ = doJSONRequest(t, client, http.MethodGet, app.BaseURL+"/v1/me", nil, nil)
	requireStatus(t, status, http.StatusUnauthorized, body)

	status, body, _ = doJSONRequest(
		t,
		client,
		http.MethodPost,
		app.BaseURL+"/v1/auth/login",
		map[string]string{"email": email, "password": oldPassword},
		nil,
	)
	requireStatus(t, status, http.StatusUnauthorized, body)

	status, body, _ = doJSONRequest(
		t,
		client,
		http.MethodPost,
		app.BaseURL+"/v1/auth/login",
		map[string]string{"email": email, "password": newPassword},
		nil,
	)
	requireStatus(t, status, http.StatusOK, body)
}
