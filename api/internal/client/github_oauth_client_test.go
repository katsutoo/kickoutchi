package client

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

type roundTripperFunc func(req *http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestGitHubOAuthClientFetchUserWithEmailFallback(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/login/oauth/access_token":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"access_token":"oauth_token","token_type":"bearer"}`))
		case "/user":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"id":42,"login":"octocat","name":"Octo Cat","email":""}`))
		case "/user/emails":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`[{"email":"secondary@example.com","primary":false,"verified":true},{"email":"primary@example.com","primary":true,"verified":true}]`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(server.Close)

	targetURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("parse test server url: %v", err)
	}

	httpClient := &http.Client{
		Timeout: 15 * time.Second,
		Transport: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
			cloned := req.Clone(req.Context())
			if req.URL.Host == "github.com" || req.URL.Host == "api.github.com" {
				cloned.URL.Scheme = targetURL.Scheme
				cloned.URL.Host = targetURL.Host
			}

			return http.DefaultTransport.RoundTrip(cloned)
		}),
	}

	githubClient, err := NewGitHubOAuthClient(GitHubOAuthClientConfig{
		ClientID:     "client_id",
		ClientSecret: "client_secret",
		RedirectURL:  "http://localhost:8080/v1/auth/oauth/github/callback",
		HTTPClient:   httpClient,
	})
	if err != nil {
		t.Fatalf("create github oauth client: %v", err)
	}

	user, err := githubClient.FetchUser(context.Background(), "oauth_code")
	if err != nil {
		t.Fatalf("fetch github oauth user: %v", err)
	}

	if user.ProviderUID != "42" {
		t.Fatalf("unexpected provider uid: %s", user.ProviderUID)
	}

	if user.Email != "primary@example.com" {
		t.Fatalf("unexpected selected email: %s", user.Email)
	}

	if user.Login != "octocat" {
		t.Fatalf("unexpected login: %s", user.Login)
	}
}

func TestGitHubOAuthClientFetchUserErrorWhenNoUsableEmail(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/login/oauth/access_token":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"access_token":"oauth_token","token_type":"bearer"}`))
		case "/user":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"id":42,"login":"octocat","name":"Octo Cat","email":""}`))
		case "/user/emails":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`[]`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(server.Close)

	targetURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("parse test server url: %v", err)
	}

	httpClient := &http.Client{
		Timeout: 15 * time.Second,
		Transport: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
			cloned := req.Clone(req.Context())
			if req.URL.Host == "github.com" || req.URL.Host == "api.github.com" {
				cloned.URL.Scheme = targetURL.Scheme
				cloned.URL.Host = targetURL.Host
			}

			return http.DefaultTransport.RoundTrip(cloned)
		}),
	}

	githubClient, err := NewGitHubOAuthClient(GitHubOAuthClientConfig{
		ClientID:     "client_id",
		ClientSecret: "client_secret",
		RedirectURL:  "http://localhost:8080/v1/auth/oauth/github/callback",
		HTTPClient:   httpClient,
	})
	if err != nil {
		t.Fatalf("create github oauth client: %v", err)
	}

	_, err = githubClient.FetchUser(context.Background(), "oauth_code")
	if err == nil {
		t.Fatalf("expected error when github account has no usable email")
	}

	if !strings.Contains(err.Error(), "no usable email") {
		t.Fatalf("unexpected error for missing github email: %v", err)
	}
}

func TestGitHubOAuthClientAuthorizationURLIncludesRequiredParameters(t *testing.T) {
	githubClient, err := NewGitHubOAuthClient(GitHubOAuthClientConfig{
		ClientID:     "client_id",
		ClientSecret: "client_secret",
		RedirectURL:  "http://localhost:8080/v1/auth/oauth/github/callback",
	})
	if err != nil {
		t.Fatalf("create github oauth client: %v", err)
	}

	authorizationURL := githubClient.AuthorizationURL("state_value")

	parsedURL, err := url.Parse(authorizationURL)
	if err != nil {
		t.Fatalf("parse authorization url: %v", err)
	}

	query := parsedURL.Query()
	if query.Get("client_id") != "client_id" {
		t.Fatalf("unexpected client_id query value")
	}

	if query.Get("redirect_uri") != "http://localhost:8080/v1/auth/oauth/github/callback" {
		t.Fatalf("unexpected redirect_uri query value")
	}

	if query.Get("state") != "state_value" {
		t.Fatalf("unexpected state query value")
	}

	if query.Get("scope") == "" {
		t.Fatalf("expected scope query value to be set")
	}
}

func TestPickGitHubEmail(t *testing.T) {
	testCases := []struct {
		name          string
		emails        []githubEmailResponse
		expectedEmail string
	}{
		{
			name: "primary and verified first",
			emails: []githubEmailResponse{
				{Email: "secondary@example.com", Primary: false, Verified: true},
				{Email: "primary@example.com", Primary: true, Verified: true},
			},
			expectedEmail: "primary@example.com",
		},
		{
			name: "fallback to verified when no primary",
			emails: []githubEmailResponse{
				{Email: "unverified@example.com", Primary: false, Verified: false},
				{Email: "verified@example.com", Primary: false, Verified: true},
			},
			expectedEmail: "verified@example.com",
		},
		{
			name: "fallback to first non-empty",
			emails: []githubEmailResponse{
				{Email: "first@example.com", Primary: false, Verified: false},
			},
			expectedEmail: "first@example.com",
		},
	}

	for _, testCase := range testCases {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			got := pickGitHubEmail(testCase.emails)
			if got != testCase.expectedEmail {
				t.Fatalf("unexpected picked email: got=%q expected=%q", got, testCase.expectedEmail)
			}
		})
	}
}

func TestGitHubOAuthClientTokenExchangeDecodeError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/login/oauth/access_token" {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"invalid": []string{"payload"}})
	}))
	t.Cleanup(server.Close)

	targetURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("parse test server url: %v", err)
	}

	httpClient := &http.Client{
		Timeout: 15 * time.Second,
		Transport: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
			cloned := req.Clone(req.Context())
			if req.URL.Host == "github.com" || req.URL.Host == "api.github.com" {
				cloned.URL.Scheme = targetURL.Scheme
				cloned.URL.Host = targetURL.Host
			}

			return http.DefaultTransport.RoundTrip(cloned)
		}),
	}

	githubClient, err := NewGitHubOAuthClient(GitHubOAuthClientConfig{
		ClientID:     "client_id",
		ClientSecret: "client_secret",
		RedirectURL:  "http://localhost:8080/v1/auth/oauth/github/callback",
		HTTPClient:   httpClient,
	})
	if err != nil {
		t.Fatalf("create github oauth client: %v", err)
	}

	_, err = githubClient.FetchUser(context.Background(), "oauth_code")
	if err == nil {
		t.Fatalf("expected token exchange error when access token missing")
	}
}
