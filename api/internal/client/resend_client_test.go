package client

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestResendClientSendEmailSuccess(t *testing.T) {
	var capturedAuthorization string
	var capturedRequest resendEmailRequest

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("unexpected method: %s", r.Method)
		}

		if r.URL.Path != "/emails" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}

		capturedAuthorization = r.Header.Get("Authorization")

		if err := json.NewDecoder(r.Body).Decode(&capturedRequest); err != nil {
			t.Fatalf("decode resend request: %v", err)
		}

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"email_123"}`))
	}))
	t.Cleanup(server.Close)

	resendClient, err := NewResendClient(ResendClientConfig{
		APIKey:     "resend_test_key",
		FromEmail:  "from@kickoutchi.dev",
		APIBaseURL: server.URL,
		HTTPClient: server.Client(),
	})
	if err != nil {
		t.Fatalf("create resend client: %v", err)
	}

	messageID, err := resendClient.SendEmail(context.Background(), "to@kickoutchi.dev", "Verify", "<p>Hello</p>", "Hello")
	if err != nil {
		t.Fatalf("send email: %v", err)
	}

	if messageID != "email_123" {
		t.Fatalf("unexpected message id: %s", messageID)
	}

	if capturedAuthorization != "Bearer resend_test_key" {
		t.Fatalf("unexpected authorization header: %s", capturedAuthorization)
	}

	if capturedRequest.From != "from@kickoutchi.dev" {
		t.Fatalf("unexpected from email: %s", capturedRequest.From)
	}

	if len(capturedRequest.To) != 1 || capturedRequest.To[0] != "to@kickoutchi.dev" {
		t.Fatalf("unexpected recipient payload: %+v", capturedRequest.To)
	}
}

func TestResendClientSendEmailNon2xx(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnprocessableEntity)
		_, _ = w.Write([]byte(`{"error":"invalid recipient"}`))
	}))
	t.Cleanup(server.Close)

	resendClient, err := NewResendClient(ResendClientConfig{
		APIKey:     "resend_test_key",
		FromEmail:  "from@kickoutchi.dev",
		APIBaseURL: server.URL,
		HTTPClient: server.Client(),
	})
	if err != nil {
		t.Fatalf("create resend client: %v", err)
	}

	_, err = resendClient.SendEmail(context.Background(), "to@kickoutchi.dev", "Verify", "<p>Hello</p>", "Hello")
	if err == nil {
		t.Fatalf("expected non-2xx resend response to return an error")
	}

	if !strings.Contains(err.Error(), "status=422") {
		t.Fatalf("expected error to mention status=422, got: %v", err)
	}
}

func TestResendClientSendEmailValidation(t *testing.T) {
	resendClient, err := NewResendClient(ResendClientConfig{
		APIKey:    "resend_test_key",
		FromEmail: "from@kickoutchi.dev",
	})
	if err != nil {
		t.Fatalf("create resend client: %v", err)
	}

	_, err = resendClient.SendEmail(context.Background(), " ", "Verify", "<p>Hello</p>", "Hello")
	if err == nil {
		t.Fatalf("expected empty recipient to return an error")
	}
}
