package handler

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	chimiddleware "github.com/go-chi/chi/v5/middleware"
	validatorv10 "github.com/go-playground/validator/v10"
	"github.com/google/uuid"

	"github.com/katsutoo/kickoutchi/api/internal/apierror"
	"github.com/katsutoo/kickoutchi/api/internal/auth"
	"github.com/katsutoo/kickoutchi/api/internal/service"
	"github.com/katsutoo/kickoutchi/api/internal/sessioncookie"
)

const (
	maxAuthRequestBodyBytes = 1 << 20
	defaultOAuthStateTTL    = 10 * time.Minute
	oauthStateCookiePrefix  = "kickoutchi_oauth_state"
)

type authService interface {
	Register(ctx context.Context, input service.RegisterInput) (service.RegisterResult, error)
	Login(ctx context.Context, input service.LoginInput) (service.LoginResult, error)
	Logout(ctx context.Context, sessionToken string) error
	ForgotPassword(ctx context.Context, email string) error
	ResetPassword(ctx context.Context, token, password string) error
	VerifyEmail(ctx context.Context, token string) error
	ResendVerificationEmail(ctx context.Context, userID uuid.UUID) error
	GitHubAuthorizationURL(state string) (string, error)
	LoginWithOAuth(ctx context.Context, input service.OAuthLoginInput) (service.LoginResult, error)
	UpdateProfile(ctx context.Context, input service.UpdateProfileInput) (service.UserView, error)
	CreateAvatarUploadURL(ctx context.Context, input service.CreateAvatarUploadURLInput) (service.CreateAvatarUploadURLResult, error)
	ConfirmAvatarUpload(ctx context.Context, input service.ConfirmAvatarUploadInput) (service.UserView, error)
	DeleteAvatar(ctx context.Context, userID uuid.UUID) (service.UserView, error)
	GetAvatarAccessURL(ctx context.Context, userID uuid.UUID) (service.AvatarAccessURLResult, error)
}

type requestValidator interface {
	Struct(value any) error
}

type SessionCookieConfig = sessioncookie.Config

type AuthHandler struct {
	authService   authService
	validator     requestValidator
	sessionCookie SessionCookieConfig
	webBaseURL    string
	oauthStateTTL time.Duration
	logger        *slog.Logger
}

type registerRequest struct {
	Email       string `json:"email" validate:"required,email,max=320"`
	Password    string `json:"password" validate:"required,min=8,max=128"`
	DisplayName string `json:"display_name" validate:"required,min=3,max=30"`
}

type loginRequest struct {
	Email    string `json:"email" validate:"required,email,max=320"`
	Password string `json:"password" validate:"required,min=8,max=128"`
}

type forgotPasswordRequest struct {
	Email string `json:"email" validate:"required,email,max=320"`
}

type resetPasswordRequest struct {
	Token    string `json:"token" validate:"required,min=20,max=512"`
	Password string `json:"password" validate:"required,min=8,max=128"`
}

type verifyEmailRequest struct {
	Token string `json:"token" validate:"required,min=20,max=512"`
}

type updateProfileRequest struct {
	DisplayName *string `json:"display_name,omitempty" validate:"omitempty,min=3,max=30"`
}

type avatarUploadURLRequest struct {
	ContentType   string `json:"content_type" validate:"required,max=128"`
	ContentLength int64  `json:"content_length" validate:"required"`
}

type confirmAvatarUploadRequest struct {
	ObjectKey string `json:"object_key" validate:"required,min=3,max=512"`
}

type userResponse struct {
	ID              string          `json:"id"`
	Email           string          `json:"email"`
	DisplayName     string          `json:"display_name"`
	Role            string          `json:"role"`
	EmailVerifiedAt *time.Time      `json:"email_verified_at,omitempty"`
	AvatarMetadata  json.RawMessage `json:"avatar_metadata"`
	InsertedAt      time.Time       `json:"inserted_at"`
	UpdatedAt       time.Time       `json:"updated_at"`
}

type authResultResponse struct {
	User userResponse `json:"user"`
}

type actionStatusResponse struct {
	Status string `json:"status"`
}

type avatarUploadURLResponse struct {
	UploadURL string            `json:"upload_url"`
	Method    string            `json:"method"`
	ObjectKey string            `json:"object_key"`
	ExpiresAt time.Time         `json:"expires_at"`
	Headers   map[string]string `json:"headers"`
}

type avatarAccessURLResponse struct {
	URL       string    `json:"url"`
	ExpiresAt time.Time `json:"expires_at"`
}

func NewAuthHandler(
	authService authService,
	validator requestValidator,
	sessionCookie SessionCookieConfig,
	webBaseURL string,
	oauthStateTTL time.Duration,
	logger *slog.Logger,
) *AuthHandler {
	if validator == nil {
		validator = noopRequestValidator{}
	}

	sessionCookie = sessioncookie.NormalizeConfig(sessionCookie)

	if oauthStateTTL <= 0 {
		oauthStateTTL = defaultOAuthStateTTL
	}

	if logger == nil {
		logger = slog.Default()
	}

	trimmedWebBaseURL := strings.TrimRight(strings.TrimSpace(webBaseURL), "/")
	if trimmedWebBaseURL == "" {
		trimmedWebBaseURL = "http://localhost:5173"
	}

	return &AuthHandler{
		authService:   authService,
		validator:     validator,
		sessionCookie: sessionCookie,
		webBaseURL:    trimmedWebBaseURL,
		oauthStateTTL: oauthStateTTL,
		logger:        logger,
	}
}

func (h *AuthHandler) currentSessionToken(r *http.Request) string {
	sessionCookie, err := r.Cookie(h.sessionCookie.Name)
	if err != nil {
		return ""
	}

	return sessionCookie.Value
}

func (h *AuthHandler) setSessionCookie(w http.ResponseWriter, token string, expiresAt time.Time) {
	sessioncookie.Set(w, h.sessionCookie, token, expiresAt)
}

func (h *AuthHandler) clearSessionCookie(w http.ResponseWriter) {
	sessioncookie.Clear(w, h.sessionCookie)
}

func normalizeOAuthProvider(provider string) string {
	return strings.ToLower(strings.TrimSpace(provider))
}

func isSupportedOAuthProvider(provider string) bool {
	return normalizeOAuthProvider(provider) == "github"
}

func oauthStateCookieName(provider string) string {
	normalizedProvider := normalizeOAuthProvider(provider)
	if normalizedProvider == "" {
		return oauthStateCookiePrefix
	}

	return oauthStateCookiePrefix + "_" + normalizedProvider
}

func oauthStateCookiePath(provider string) string {
	return "/v1/auth/oauth/" + normalizeOAuthProvider(provider) + "/callback"
}

func (h *AuthHandler) setOAuthStateCookie(w http.ResponseWriter, provider, state string) {
	http.SetCookie(w, &http.Cookie{
		Name:     oauthStateCookieName(provider),
		Value:    state,
		Path:     oauthStateCookiePath(provider),
		Domain:   h.sessionCookie.Domain,
		Expires:  time.Now().UTC().Add(h.oauthStateTTL),
		MaxAge:   int(h.oauthStateTTL.Seconds()),
		HttpOnly: true,
		Secure:   h.sessionCookie.Secure,
		SameSite: sessioncookie.ParseSameSite(h.sessionCookie.SameSite),
	})
}

func (h *AuthHandler) clearOAuthStateCookie(w http.ResponseWriter, provider string) {
	http.SetCookie(w, &http.Cookie{
		Name:     oauthStateCookieName(provider),
		Value:    "",
		Path:     oauthStateCookiePath(provider),
		Domain:   h.sessionCookie.Domain,
		Expires:  time.Unix(0, 0).UTC(),
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   h.sessionCookie.Secure,
		SameSite: sessioncookie.ParseSameSite(h.sessionCookie.SameSite),
	})
}

func (h *AuthHandler) validateOAuthState(r *http.Request, provider, state string) bool {
	if strings.TrimSpace(state) == "" {
		return false
	}

	cookie, err := r.Cookie(oauthStateCookieName(provider))
	if err != nil {
		return false
	}

	if strings.TrimSpace(cookie.Value) == "" {
		return false
	}

	return subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(state)) == 1
}

func (h *AuthHandler) generateOAuthState() (string, error) {
	state, _, err := auth.GenerateOAuthState()
	if err != nil {
		return "", err
	}

	return state, nil
}

func (h *AuthHandler) redirectOAuthError(w http.ResponseWriter, r *http.Request, reason string) {
	values := url.Values{}
	values.Set("error", reason)
	http.Redirect(w, r, h.webBaseURL+"/login?"+values.Encode(), http.StatusFound)
}

func requestRemoteIP(remoteAddr string) string {
	host, _, err := net.SplitHostPort(strings.TrimSpace(remoteAddr))
	if err == nil {
		return host
	}

	return strings.TrimSpace(remoteAddr)
}

func decodeRequestBody(w http.ResponseWriter, r *http.Request, target any) error {
	r.Body = http.MaxBytesReader(w, r.Body, maxAuthRequestBodyBytes)
	defer r.Body.Close()

	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()

	if err := decoder.Decode(target); err != nil {
		return err
	}

	// Enforce exactly one JSON object in the request body. The second decode
	// must hit io.EOF, otherwise the client sent trailing data.
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return err
	}

	return nil
}

func writeValidationError(w http.ResponseWriter, err error) {
	details := map[string]any{}

	var validationErrors validatorv10.ValidationErrors
	if errors.As(err, &validationErrors) {
		fields := make(map[string]string, len(validationErrors))
		for _, validationError := range validationErrors {
			fields[validationError.Field()] = validationError.Tag()
		}
		details["fields"] = fields
	}

	apierror.WriteError(w, &apierror.Error{
		Status:  http.StatusBadRequest,
		Code:    "VALIDATION_ERROR",
		Message: "validation failed",
		Details: details,
		Err:     err,
	})
}

func writeInvalidRequest(w http.ResponseWriter, err error) {
	apierror.WriteError(w, apierror.New(http.StatusBadRequest, "INVALID_REQUEST", "invalid request body", err))
}

func writeConflict(w http.ResponseWriter, code, message string, err error) {
	apierror.WriteError(w, apierror.New(http.StatusConflict, code, message, err))
}

func (h *AuthHandler) writeInternalServerError(r *http.Request, w http.ResponseWriter, err error) {
	logger := h.logger
	if logger == nil {
		logger = slog.Default()
	}

	if r != nil {
		logger.Error(
			"request_internal_error",
			slog.String("request_id", chimiddleware.GetReqID(r.Context())),
			slog.String("method", r.Method),
			slog.String("path", r.URL.Path),
			slog.Any("err", err),
		)
	} else {
		logger.Error("request_internal_error", slog.Any("err", err))
	}

	apierror.WriteError(w, apierror.New(http.StatusInternalServerError, "INTERNAL_ERROR", "internal server error", err))
}

func toUserResponse(user service.UserView) userResponse {
	avatar := user.AvatarMetadata
	if len(avatar) == 0 {
		avatar = json.RawMessage("{}")
	}

	return userResponse{
		ID:              user.ID.String(),
		Email:           user.Email,
		DisplayName:     user.DisplayName,
		Role:            user.Role,
		EmailVerifiedAt: user.EmailVerifiedAt,
		AvatarMetadata:  avatar,
		InsertedAt:      user.InsertedAt,
		UpdatedAt:       user.UpdatedAt,
	}
}

type noopRequestValidator struct{}

func (noopRequestValidator) Struct(any) error {
	return nil
}
