//go:build integration
// +build integration

package integration

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

type errorEnvelope struct {
	Error   string         `json:"error"`
	Code    string         `json:"code"`
	Details map[string]any `json:"details"`
}

type authResultEnvelope struct {
	Data struct {
		User struct {
			ID              string          `json:"id"`
			Email           string          `json:"email"`
			DisplayName     string          `json:"display_name"`
			Role            string          `json:"role"`
			EmailVerifiedAt *time.Time      `json:"email_verified_at"`
			AvatarMetadata  json.RawMessage `json:"avatar_metadata"`
		} `json:"user"`
	} `json:"data"`
}

func doJSONRequest(
	t *testing.T,
	client *http.Client,
	method,
	targetURL string,
	body any,
	headers map[string]string,
) (int, []byte, http.Header) {
	t.Helper()

	var requestBody io.Reader
	if body != nil {
		payload, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal request body: %v", err)
		}
		requestBody = bytes.NewReader(payload)
	}

	req, err := http.NewRequest(method, targetURL, requestBody)
	if err != nil {
		t.Fatalf("create request: %v", err)
	}

	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	for key, value := range headers {
		req.Header.Set(key, value)
	}

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("execute request: %v", err)
	}
	defer resp.Body.Close()

	responseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read response body: %v", err)
	}

	return resp.StatusCode, responseBody, resp.Header.Clone()
}

func mustDecodeJSON[T any](t *testing.T, payload []byte) T {
	t.Helper()

	var decoded T
	if err := json.Unmarshal(payload, &decoded); err != nil {
		t.Fatalf("decode json payload: %v body=%s", err, strings.TrimSpace(string(payload)))
	}

	return decoded
}

func requireStatus(t *testing.T, gotStatus, expectedStatus int, responseBody []byte) {
	t.Helper()

	if gotStatus != expectedStatus {
		t.Fatalf(
			"unexpected status: got=%d expected=%d body=%s",
			gotStatus,
			expectedStatus,
			strings.TrimSpace(string(responseBody)),
		)
	}
}

func uniqueEmail(prefix string) string {
	return fmt.Sprintf("%s_%d@example.com", prefix, time.Now().UnixNano())
}

func uniqueDisplayName(prefix string) string {
	value := fmt.Sprintf("%s_%d", prefix, time.Now().UnixNano())
	if len(value) > 30 {
		return value[:30]
	}

	return value
}
