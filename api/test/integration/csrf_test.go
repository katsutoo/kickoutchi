//go:build integration
// +build integration

package integration

import (
	"net/http"
	"testing"

	"github.com/katsutoo/kickoutchi/api/test/testutil"
)

func TestCSRFOriginEnforcementIntegration(t *testing.T) {
	app := testutil.NewIntegrationApp(t, testutil.IntegrationAppOptions{})
	client := app.NewCookieClient(t)

	status, body, _ := doJSONRequest(
		t,
		client,
		http.MethodPost,
		app.BaseURL+"/v1/auth/register",
		map[string]string{
			"email":        uniqueEmail("csrf"),
			"password":     "Str0ngPassw0rd!",
			"display_name": uniqueDisplayName("csrf_user"),
		},
		nil,
	)
	requireStatus(t, status, http.StatusCreated, body)

	status, body, _ = doJSONRequest(
		t,
		client,
		http.MethodPatch,
		app.BaseURL+"/v1/me",
		map[string]string{"display_name": uniqueDisplayName("no_origin")},
		nil,
	)
	requireStatus(t, status, http.StatusForbidden, body)

	errorResponse := mustDecodeJSON[errorEnvelope](t, body)
	if errorResponse.Code != "CSRF_ORIGIN_INVALID" {
		t.Fatalf("unexpected csrf error code without origin: %s", errorResponse.Code)
	}

	status, body, _ = doJSONRequest(
		t,
		client,
		http.MethodPatch,
		app.BaseURL+"/v1/me",
		map[string]string{"display_name": uniqueDisplayName("bad_origin")},
		map[string]string{"Origin": "http://evil.test"},
	)
	requireStatus(t, status, http.StatusForbidden, body)

	status, body, _ = doJSONRequest(
		t,
		client,
		http.MethodPatch,
		app.BaseURL+"/v1/me",
		map[string]string{"display_name": uniqueDisplayName("good_origin")},
		map[string]string{"Origin": app.AllowedOrigin},
	)
	requireStatus(t, status, http.StatusOK, body)
}
