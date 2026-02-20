package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type GitHubOAuthClientConfig struct {
	ClientID     string
	ClientSecret string
	RedirectURL  string
	HTTPClient   *http.Client
}

type GitHubOAuthClient struct {
	clientID     string
	clientSecret string
	redirectURL  string
	http         *http.Client
}

type GitHubOAuthUser struct {
	ProviderUID string
	Email       string
	Login       string
	Name        string
}

type githubTokenResponse struct {
	AccessToken      string `json:"access_token"`
	TokenType        string `json:"token_type"`
	Scope            string `json:"scope"`
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

type githubUserResponse struct {
	ID    int64  `json:"id"`
	Login string `json:"login"`
	Name  string `json:"name"`
	Email string `json:"email"`
}

type githubEmailResponse struct {
	Email    string `json:"email"`
	Primary  bool   `json:"primary"`
	Verified bool   `json:"verified"`
}

func NewGitHubOAuthClient(cfg GitHubOAuthClientConfig) (*GitHubOAuthClient, error) {
	clientID := strings.TrimSpace(cfg.ClientID)
	clientSecret := strings.TrimSpace(cfg.ClientSecret)
	redirectURL := strings.TrimSpace(cfg.RedirectURL)

	if clientID == "" || clientSecret == "" || redirectURL == "" {
		return nil, errors.New("github OAuth client requires client id, client secret, and redirect URL")
	}

	httpClient := cfg.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 15 * time.Second}
	}

	return &GitHubOAuthClient{
		clientID:     clientID,
		clientSecret: clientSecret,
		redirectURL:  redirectURL,
		http:         httpClient,
	}, nil
}

func (c *GitHubOAuthClient) AuthorizationURL(state string) string {
	values := url.Values{}
	values.Set("client_id", c.clientID)
	values.Set("redirect_uri", c.redirectURL)
	values.Set("scope", "read:user user:email")
	values.Set("state", state)

	return "https://github.com/login/oauth/authorize?" + values.Encode()
}

func (c *GitHubOAuthClient) FetchUser(ctx context.Context, code string) (GitHubOAuthUser, error) {
	accessToken, err := c.exchangeCode(ctx, code)
	if err != nil {
		return GitHubOAuthUser{}, err
	}

	user, err := c.fetchUser(ctx, accessToken)
	if err != nil {
		return GitHubOAuthUser{}, err
	}

	email := strings.ToLower(strings.TrimSpace(user.Email))
	if email == "" {
		emails, err := c.fetchEmails(ctx, accessToken)
		if err != nil {
			return GitHubOAuthUser{}, err
		}

		email = pickGitHubEmail(emails)
	}

	if email == "" {
		return GitHubOAuthUser{}, errors.New("github account has no usable email")
	}

	if user.ID == 0 {
		return GitHubOAuthUser{}, errors.New("github account has invalid user id")
	}

	providerUID := strconv.FormatInt(user.ID, 10)

	return GitHubOAuthUser{
		ProviderUID: providerUID,
		Email:       email,
		Login:       strings.TrimSpace(user.Login),
		Name:        strings.TrimSpace(user.Name),
	}, nil
}

func (c *GitHubOAuthClient) exchangeCode(ctx context.Context, code string) (string, error) {
	trimmedCode := strings.TrimSpace(code)
	if trimmedCode == "" {
		return "", errors.New("github OAuth code is required")
	}

	values := url.Values{}
	values.Set("client_id", c.clientID)
	values.Set("client_secret", c.clientSecret)
	values.Set("code", trimmedCode)
	values.Set("redirect_uri", c.redirectURL)

	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		"https://github.com/login/oauth/access_token",
		strings.NewReader(values.Encode()),
	)
	if err != nil {
		return "", fmt.Errorf("create github token request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "kickoutchi-api")

	resp, err := c.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("exchange github code: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", fmt.Errorf("read github token response: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("github token exchange failed: status=%d body=%s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var tokenResponse githubTokenResponse
	if err := json.Unmarshal(body, &tokenResponse); err != nil {
		return "", fmt.Errorf("decode github token response: %w", err)
	}

	if tokenResponse.Error != "" {
		return "", fmt.Errorf("github token exchange error: %s (%s)", tokenResponse.Error, tokenResponse.ErrorDescription)
	}

	if strings.TrimSpace(tokenResponse.AccessToken) == "" {
		return "", errors.New("github token response missing access token")
	}

	return tokenResponse.AccessToken, nil
}

func (c *GitHubOAuthClient) fetchUser(ctx context.Context, accessToken string) (githubUserResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.github.com/user", nil)
	if err != nil {
		return githubUserResponse{}, fmt.Errorf("create github user request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("User-Agent", "kickoutchi-api")

	resp, err := c.http.Do(req)
	if err != nil {
		return githubUserResponse{}, fmt.Errorf("fetch github user: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return githubUserResponse{}, fmt.Errorf("read github user response: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return githubUserResponse{}, fmt.Errorf("github user request failed: status=%d body=%s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var user githubUserResponse
	if err := json.Unmarshal(body, &user); err != nil {
		return githubUserResponse{}, fmt.Errorf("decode github user response: %w", err)
	}

	return user, nil
}

func (c *GitHubOAuthClient) fetchEmails(ctx context.Context, accessToken string) ([]githubEmailResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.github.com/user/emails", nil)
	if err != nil {
		return nil, fmt.Errorf("create github emails request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("User-Agent", "kickoutchi-api")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch github emails: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("read github emails response: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("github emails request failed: status=%d body=%s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var emails []githubEmailResponse
	if err := json.Unmarshal(body, &emails); err != nil {
		return nil, fmt.Errorf("decode github emails response: %w", err)
	}

	return emails, nil
}

func pickGitHubEmail(emails []githubEmailResponse) string {
	for _, email := range emails {
		if email.Primary && email.Verified {
			return strings.ToLower(strings.TrimSpace(email.Email))
		}
	}

	for _, email := range emails {
		if email.Verified {
			return strings.ToLower(strings.TrimSpace(email.Email))
		}
	}

	for _, email := range emails {
		trimmed := strings.ToLower(strings.TrimSpace(email.Email))
		if trimmed != "" {
			return trimmed
		}
	}

	return ""
}
