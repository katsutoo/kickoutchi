package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/katsutoo/kickoutchi/api/internal/service"
	appvalidator "github.com/katsutoo/kickoutchi/api/internal/validator"
)

type stubAuthService struct {
	registerFn               func(ctx context.Context, input service.RegisterInput) (service.RegisterResult, error)
	loginFn                  func(ctx context.Context, input service.LoginInput) (service.LoginResult, error)
	logoutFn                 func(ctx context.Context, sessionToken string) error
	forgotPasswordFn         func(ctx context.Context, email string) error
	resetPasswordFn          func(ctx context.Context, token, password string) error
	verifyEmailFn            func(ctx context.Context, token string) error
	resendVerificationFn     func(ctx context.Context, userID uuid.UUID) error
	githubAuthorizationURLFn func(state string) (string, error)
	loginWithOAuthFn         func(ctx context.Context, input service.OAuthLoginInput) (service.LoginResult, error)
	updateProfileFn          func(ctx context.Context, input service.UpdateProfileInput) (service.UserView, error)
	createAvatarUploadURLFn  func(ctx context.Context, input service.CreateAvatarUploadURLInput) (service.CreateAvatarUploadURLResult, error)
	confirmAvatarUploadFn    func(ctx context.Context, input service.ConfirmAvatarUploadInput) (service.UserView, error)
	deleteAvatarFn           func(ctx context.Context, userID uuid.UUID) (service.UserView, error)
}

func (s *stubAuthService) Register(ctx context.Context, input service.RegisterInput) (service.RegisterResult, error) {
	if s.registerFn != nil {
		return s.registerFn(ctx, input)
	}

	return service.RegisterResult{}, nil
}

func (s *stubAuthService) Login(ctx context.Context, input service.LoginInput) (service.LoginResult, error) {
	if s.loginFn != nil {
		return s.loginFn(ctx, input)
	}

	return service.LoginResult{}, nil
}

func (s *stubAuthService) Logout(ctx context.Context, sessionToken string) error {
	if s.logoutFn != nil {
		return s.logoutFn(ctx, sessionToken)
	}

	return nil
}

func (s *stubAuthService) ForgotPassword(ctx context.Context, email string) error {
	if s.forgotPasswordFn != nil {
		return s.forgotPasswordFn(ctx, email)
	}

	return nil
}

func (s *stubAuthService) ResetPassword(ctx context.Context, token, password string) error {
	if s.resetPasswordFn != nil {
		return s.resetPasswordFn(ctx, token, password)
	}

	return nil
}

func (s *stubAuthService) VerifyEmail(ctx context.Context, token string) error {
	if s.verifyEmailFn != nil {
		return s.verifyEmailFn(ctx, token)
	}

	return nil
}

func (s *stubAuthService) ResendVerificationEmail(ctx context.Context, userID uuid.UUID) error {
	if s.resendVerificationFn != nil {
		return s.resendVerificationFn(ctx, userID)
	}

	return nil
}

func (s *stubAuthService) GitHubAuthorizationURL(state string) (string, error) {
	if s.githubAuthorizationURLFn != nil {
		return s.githubAuthorizationURLFn(state)
	}

	return "", nil
}

func (s *stubAuthService) LoginWithOAuth(ctx context.Context, input service.OAuthLoginInput) (service.LoginResult, error) {
	if s.loginWithOAuthFn != nil {
		return s.loginWithOAuthFn(ctx, input)
	}

	return service.LoginResult{}, nil
}

func (s *stubAuthService) UpdateProfile(ctx context.Context, input service.UpdateProfileInput) (service.UserView, error) {
	if s.updateProfileFn != nil {
		return s.updateProfileFn(ctx, input)
	}

	return service.UserView{}, nil
}

func (s *stubAuthService) CreateAvatarUploadURL(ctx context.Context, input service.CreateAvatarUploadURLInput) (service.CreateAvatarUploadURLResult, error) {
	if s.createAvatarUploadURLFn != nil {
		return s.createAvatarUploadURLFn(ctx, input)
	}

	return service.CreateAvatarUploadURLResult{}, nil
}

func (s *stubAuthService) ConfirmAvatarUpload(ctx context.Context, input service.ConfirmAvatarUploadInput) (service.UserView, error) {
	if s.confirmAvatarUploadFn != nil {
		return s.confirmAvatarUploadFn(ctx, input)
	}

	return service.UserView{}, nil
}

func (s *stubAuthService) DeleteAvatar(ctx context.Context, userID uuid.UUID) (service.UserView, error) {
	if s.deleteAvatarFn != nil {
		return s.deleteAvatarFn(ctx, userID)
	}

	return service.UserView{}, nil
}

func TestAuthHandlerRegisterErrorMapping(t *testing.T) {
	testCases := []struct {
		name       string
		serviceErr error
		wantStatus int
		wantCode   string
	}{
		{
			name:       "invalid input",
			serviceErr: service.ErrInvalidRegisterInput,
			wantStatus: http.StatusBadRequest,
			wantCode:   "INVALID_REQUEST",
		},
		{
			name:       "email conflict",
			serviceErr: service.ErrEmailAlreadyInUse,
			wantStatus: http.StatusConflict,
			wantCode:   "EMAIL_ALREADY_IN_USE",
		},
		{
			name:       "display name conflict",
			serviceErr: service.ErrDisplayNameAlreadyInUse,
			wantStatus: http.StatusConflict,
			wantCode:   "DISPLAY_NAME_ALREADY_IN_USE",
		},
	}

	for _, testCase := range testCases {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			h := newTestAuthHandler(t, &stubAuthService{
				registerFn: func(context.Context, service.RegisterInput) (service.RegisterResult, error) {
					return service.RegisterResult{}, testCase.serviceErr
				},
			})

			req := httptest.NewRequest(http.MethodPost, "/v1/auth/register", strings.NewReader(`{"email":"test@example.com","password":"Str0ngPassw0rd!","display_name":"test_user"}`))
			req.Header.Set("Content-Type", "application/json")
			recorder := httptest.NewRecorder()

			h.Register(recorder, req)

			if recorder.Code != testCase.wantStatus {
				t.Fatalf("unexpected status: got=%d expected=%d", recorder.Code, testCase.wantStatus)
			}

			errorPayload := decodeErrorEnvelope(t, recorder.Body.Bytes())
			if errorPayload.Code != testCase.wantCode {
				t.Fatalf("unexpected error code: got=%s expected=%s", errorPayload.Code, testCase.wantCode)
			}
		})
	}
}

func TestAuthHandlerRegisterRejectsUnknownFields(t *testing.T) {
	h := newTestAuthHandler(t, &stubAuthService{})

	req := httptest.NewRequest(http.MethodPost, "/v1/auth/register", strings.NewReader(`{"email":"test@example.com","password":"Str0ngPassw0rd!","display_name":"test_user","extra":"bad"}`))
	req.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()

	h.Register(recorder, req)

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("unexpected status: got=%d expected=%d", recorder.Code, http.StatusBadRequest)
	}

	errorPayload := decodeErrorEnvelope(t, recorder.Body.Bytes())
	if errorPayload.Code != "INVALID_REQUEST" {
		t.Fatalf("unexpected error code: got=%s expected=%s", errorPayload.Code, "INVALID_REQUEST")
	}
}

func TestAuthHandlerLoginInvalidCredentialsMapping(t *testing.T) {
	h := newTestAuthHandler(t, &stubAuthService{
		loginFn: func(context.Context, service.LoginInput) (service.LoginResult, error) {
			return service.LoginResult{}, service.ErrInvalidCredentials
		},
	})

	req := httptest.NewRequest(http.MethodPost, "/v1/auth/login", strings.NewReader(`{"email":"test@example.com","password":"wrong_password"}`))
	req.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()

	h.Login(recorder, req)

	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("unexpected status: got=%d expected=%d", recorder.Code, http.StatusUnauthorized)
	}

	errorPayload := decodeErrorEnvelope(t, recorder.Body.Bytes())
	if errorPayload.Code != "INVALID_CREDENTIALS" {
		t.Fatalf("unexpected error code: got=%s expected=%s", errorPayload.Code, "INVALID_CREDENTIALS")
	}
}

func TestAuthHandlerVerifyEmailTokenMapping(t *testing.T) {
	h := newTestAuthHandler(t, &stubAuthService{
		verifyEmailFn: func(context.Context, string) error {
			return service.ErrInvalidOrExpiredVerificationToken
		},
	})

	req := httptest.NewRequest(http.MethodPost, "/v1/auth/verify-email", strings.NewReader(`{"token":"invalid-token-value-12345"}`))
	req.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()

	h.VerifyEmail(recorder, req)

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("unexpected status: got=%d expected=%d", recorder.Code, http.StatusBadRequest)
	}

	errorPayload := decodeErrorEnvelope(t, recorder.Body.Bytes())
	if errorPayload.Code != "INVALID_OR_EXPIRED_TOKEN" {
		t.Fatalf("unexpected error code: got=%s expected=%s", errorPayload.Code, "INVALID_OR_EXPIRED_TOKEN")
	}
}

func newTestAuthHandler(t *testing.T, authService authService) *AuthHandler {
	t.Helper()

	return NewAuthHandler(
		authService,
		appvalidator.New(),
		SessionCookieConfig{
			Name:     "kickoutchi_session",
			Secure:   false,
			SameSite: "lax",
			TTL:      time.Hour,
		},
		"http://localhost:5173",
		10*time.Minute,
	)
}

func decodeErrorEnvelope(t *testing.T, body []byte) errorEnvelope {
	t.Helper()

	var response errorEnvelope
	if err := json.Unmarshal(body, &response); err != nil {
		t.Fatalf("decode error envelope: %v", err)
	}

	return response
}

type errorEnvelope struct {
	Error   string         `json:"error"`
	Code    string         `json:"code"`
	Details map[string]any `json:"details"`
}
