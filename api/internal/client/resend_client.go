package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type ResendClientConfig struct {
	APIKey     string
	FromEmail  string
	APIBaseURL string
	HTTPClient *http.Client
}

type ResendClient struct {
	apiKey    string
	fromEmail string
	baseURL   string
	http      *http.Client
}

type resendEmailRequest struct {
	From    string   `json:"from"`
	To      []string `json:"to"`
	Subject string   `json:"subject"`
	HTML    string   `json:"html,omitempty"`
	Text    string   `json:"text,omitempty"`
}

type resendEmailResponse struct {
	ID    string `json:"id"`
	Error string `json:"error"`
}

func NewResendClient(cfg ResendClientConfig) (*ResendClient, error) {
	apiKey := strings.TrimSpace(cfg.APIKey)
	if apiKey == "" {
		return nil, errors.New("resend API key is required")
	}

	fromEmail := strings.TrimSpace(cfg.FromEmail)
	if fromEmail == "" {
		return nil, errors.New("resend from email is required")
	}

	baseURL := strings.TrimSpace(cfg.APIBaseURL)
	if baseURL == "" {
		baseURL = "https://api.resend.com"
	}

	httpClient := cfg.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 15 * time.Second}
	}

	return &ResendClient{
		apiKey:    apiKey,
		fromEmail: fromEmail,
		baseURL:   strings.TrimRight(baseURL, "/"),
		http:      httpClient,
	}, nil
}

func (c *ResendClient) SendEmail(ctx context.Context, toEmail, subject, htmlBody, textBody string) (string, error) {
	to := strings.TrimSpace(toEmail)
	if to == "" {
		return "", errors.New("recipient email is required")
	}

	payload := resendEmailRequest{
		From:    c.fromEmail,
		To:      []string{to},
		Subject: subject,
		HTML:    htmlBody,
		Text:    textBody,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("marshal resend payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/emails", bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("create resend request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.apiKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("send resend request: %w", err)
	}
	defer resp.Body.Close()

	responseBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", fmt.Errorf("read resend response: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("resend request failed: status=%d body=%s", resp.StatusCode, strings.TrimSpace(string(responseBody)))
	}

	var parsedResponse resendEmailResponse
	if len(responseBody) > 0 {
		if err := json.Unmarshal(responseBody, &parsedResponse); err != nil {
			return "", fmt.Errorf("decode resend response: %w", err)
		}
	}

	if parsedResponse.Error != "" {
		return "", fmt.Errorf("resend API returned error: %s", parsedResponse.Error)
	}

	return parsedResponse.ID, nil
}
