package handler

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	validatorv10 "github.com/go-playground/validator/v10"
	"github.com/google/uuid"

	"github.com/katsutoo/kickoutchi/api/internal/apierror"
	"github.com/katsutoo/kickoutchi/api/internal/auth"
	appmiddleware "github.com/katsutoo/kickoutchi/api/internal/middleware"
	"github.com/katsutoo/kickoutchi/api/internal/service"
)

const (
	maxAuthRequestBodyBytes = 1 << 20
	defaultOAuthStateTTL    = 10 * time.Minute
	oauthStateCookieName    = "kickoutchi_oauth_state"
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
}

type requestValidator interface {
	Struct(value any) error
}

type SessionCookieConfig struct {
	Name     string
	Domain   string
	Secure   bool
	SameSite string
	TTL      time.Duration
}

type AuthHandler struct {
	authService   authService
	validator     requestValidator
	sessionCookie SessionCookieConfig
	webBaseURL    string
	oauthStateTTL time.Duration
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
	DisplayName    *string         `json:"display_name,omitempty" validate:"omitempty,min=3,max=30"`
	AvatarMetadata json.RawMessage `json:"avatar_metadata,omitempty"`
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

func NewAuthHandler(
	authService authService,
	validator requestValidator,
	sessionCookie SessionCookieConfig,
	webBaseURL string,
	oauthStateTTL time.Duration,
) *AuthHandler {
	if validator == nil {
		validator = noopRequestValidator{}
	}

	if sessionCookie.Name == "" {
		sessionCookie.Name = "kickoutchi_session"
	}

	if sessionCookie.TTL <= 0 {
		sessionCookie.TTL = 30 * 24 * time.Hour
	}

	if oauthStateTTL <= 0 {
		oauthStateTTL = defaultOAuthStateTTL
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
	}
}

func (h *AuthHandler) Register(w http.ResponseWriter, r *http.Request) {
	var req registerRequest
	if err := decodeRequestBody(w, r, &req); err != nil {
		writeInvalidRequest(w, err)
		return
	}

	if err := h.validator.Struct(req); err != nil {
		writeValidationError(w, err)
		return
	}

	result, err := h.authService.Register(r.Context(), service.RegisterInput{
		Email:       req.Email,
		Password:    req.Password,
		DisplayName: req.DisplayName,
		RemoteIP:    requestRemoteIP(r.RemoteAddr),
		UserAgent:   r.UserAgent(),
	})
	if err != nil {
		switch {
		case errors.Is(err, service.ErrInvalidRegisterInput):
			writeInvalidRequest(w, err)
		case errors.Is(err, service.ErrEmailAlreadyInUse):
			writeConflict(w, "EMAIL_ALREADY_IN_USE", "email is already in use", err)
		case errors.Is(err, service.ErrDisplayNameAlreadyInUse):
			writeConflict(w, "DISPLAY_NAME_ALREADY_IN_USE", "display name is already in use", err)
		default:
			writeInternalError(w, err)
		}
		return
	}

	h.setSessionCookie(w, result.Session.Token, result.Session.ExpiresAt)

	_ = apierror.WriteJSON(w, http.StatusCreated, apierror.DataEnvelope[authResultResponse]{
		Data: authResultResponse{User: toUserResponse(result.User)},
	})
}

func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if err := decodeRequestBody(w, r, &req); err != nil {
		writeInvalidRequest(w, err)
		return
	}

	if err := h.validator.Struct(req); err != nil {
		writeValidationError(w, err)
		return
	}

	currentSessionToken := h.currentSessionToken(r)

	result, err := h.authService.Login(r.Context(), service.LoginInput{
		Email:               req.Email,
		Password:            req.Password,
		CurrentSessionToken: currentSessionToken,
		RemoteIP:            requestRemoteIP(r.RemoteAddr),
		UserAgent:           r.UserAgent(),
	})
	if err != nil {
		switch {
		case errors.Is(err, service.ErrInvalidLoginInput):
			writeInvalidRequest(w, err)
		case errors.Is(err, service.ErrInvalidCredentials):
			apierror.WriteError(w, apierror.New(http.StatusUnauthorized, "INVALID_CREDENTIALS", "invalid email or password", err))
		default:
			writeInternalError(w, err)
		}
		return
	}

	h.setSessionCookie(w, result.Session.Token, result.Session.ExpiresAt)

	_ = apierror.WriteJSON(w, http.StatusOK, apierror.DataEnvelope[authResultResponse]{
		Data: authResultResponse{User: toUserResponse(result.User)},
	})
}

func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	if err := h.authService.Logout(r.Context(), h.currentSessionToken(r)); err != nil {
		writeInternalError(w, err)
		return
	}

	h.clearSessionCookie(w)

	_ = apierror.WriteJSON(w, http.StatusOK, apierror.DataEnvelope[actionStatusResponse]{
		Data: actionStatusResponse{Status: "ok"},
	})
}

func (h *AuthHandler) ForgotPassword(w http.ResponseWriter, r *http.Request) {
	var req forgotPasswordRequest
	if err := decodeRequestBody(w, r, &req); err != nil {
		writeInvalidRequest(w, err)
		return
	}

	if err := h.validator.Struct(req); err != nil {
		writeValidationError(w, err)
		return
	}

	if err := h.authService.ForgotPassword(r.Context(), req.Email); err != nil {
		switch {
		case errors.Is(err, service.ErrInvalidForgotPasswordInput):
			writeInvalidRequest(w, err)
		default:
			writeInternalError(w, err)
		}
		return
	}

	_ = apierror.WriteJSON(w, http.StatusOK, apierror.DataEnvelope[actionStatusResponse]{
		Data: actionStatusResponse{Status: "ok"},
	})
}

func (h *AuthHandler) ResetPassword(w http.ResponseWriter, r *http.Request) {
	var req resetPasswordRequest
	if err := decodeRequestBody(w, r, &req); err != nil {
		writeInvalidRequest(w, err)
		return
	}

	if err := h.validator.Struct(req); err != nil {
		writeValidationError(w, err)
		return
	}

	if err := h.authService.ResetPassword(r.Context(), req.Token, req.Password); err != nil {
		switch {
		case errors.Is(err, service.ErrInvalidResetPasswordInput):
			writeInvalidRequest(w, err)
		case errors.Is(err, service.ErrInvalidOrExpiredResetToken):
			apierror.WriteError(w, apierror.New(http.StatusBadRequest, "INVALID_OR_EXPIRED_TOKEN", "token is invalid or expired", err))
		default:
			writeInternalError(w, err)
		}
		return
	}

	_ = apierror.WriteJSON(w, http.StatusOK, apierror.DataEnvelope[actionStatusResponse]{
		Data: actionStatusResponse{Status: "ok"},
	})
}

func (h *AuthHandler) VerifyEmail(w http.ResponseWriter, r *http.Request) {
	var req verifyEmailRequest
	if err := decodeRequestBody(w, r, &req); err != nil {
		writeInvalidRequest(w, err)
		return
	}

	if err := h.validator.Struct(req); err != nil {
		writeValidationError(w, err)
		return
	}

	if err := h.authService.VerifyEmail(r.Context(), req.Token); err != nil {
		switch {
		case errors.Is(err, service.ErrInvalidVerifyEmailInput):
			writeInvalidRequest(w, err)
		case errors.Is(err, service.ErrInvalidOrExpiredVerificationToken):
			apierror.WriteError(w, apierror.New(http.StatusBadRequest, "INVALID_OR_EXPIRED_TOKEN", "token is invalid or expired", err))
		default:
			writeInternalError(w, err)
		}
		return
	}

	_ = apierror.WriteJSON(w, http.StatusOK, apierror.DataEnvelope[actionStatusResponse]{
		Data: actionStatusResponse{Status: "ok"},
	})
}

func (h *AuthHandler) ResendVerification(w http.ResponseWriter, r *http.Request) {
	authSession, ok := appmiddleware.AuthUserFromContext(r.Context())
	if !ok {
		apierror.WriteError(w, apierror.New(http.StatusUnauthorized, "UNAUTHORIZED", "authentication required", nil))
		return
	}

	if err := h.authService.ResendVerificationEmail(r.Context(), authSession.ID); err != nil {
		switch {
		case errors.Is(err, service.ErrInvalidSession):
			apierror.WriteError(w, apierror.New(http.StatusUnauthorized, "UNAUTHORIZED", "authentication required", err))
		default:
			writeInternalError(w, err)
		}
		return
	}

	_ = apierror.WriteJSON(w, http.StatusOK, apierror.DataEnvelope[actionStatusResponse]{
		Data: actionStatusResponse{Status: "ok"},
	})
}

func (h *AuthHandler) OAuthStart(w http.ResponseWriter, r *http.Request) {
	provider := strings.ToLower(strings.TrimSpace(chi.URLParam(r, "provider")))
	if provider != "github" {
		apierror.WriteError(w, apierror.New(http.StatusBadRequest, "INVALID_OAUTH_PROVIDER", "invalid oauth provider", service.ErrInvalidOAuthProvider))
		return
	}

	state, err := h.generateOAuthState()
	if err != nil {
		writeInternalError(w, err)
		return
	}

	authorizationURL, err := h.authService.GitHubAuthorizationURL(state)
	if err != nil {
		switch {
		case errors.Is(err, service.ErrOAuthUnavailable):
			apierror.WriteError(w, apierror.New(http.StatusServiceUnavailable, "OAUTH_UNAVAILABLE", "oauth provider unavailable", err))
		default:
			writeInternalError(w, err)
		}
		return
	}

	h.setOAuthStateCookie(w, state)
	http.Redirect(w, r, authorizationURL, http.StatusFound)
}

func (h *AuthHandler) OAuthCallback(w http.ResponseWriter, r *http.Request) {
	provider := strings.ToLower(strings.TrimSpace(chi.URLParam(r, "provider")))
	if provider != "github" {
		h.redirectOAuthError(w, r, "invalid_provider")
		return
	}

	state := strings.TrimSpace(r.URL.Query().Get("state"))
	if !h.validateOAuthState(r, state) {
		h.clearOAuthStateCookie(w)
		h.redirectOAuthError(w, r, "invalid_state")
		return
	}
	h.clearOAuthStateCookie(w)

	result, err := h.authService.LoginWithOAuth(r.Context(), service.OAuthLoginInput{
		Provider:            provider,
		Code:                strings.TrimSpace(r.URL.Query().Get("code")),
		CurrentSessionToken: h.currentSessionToken(r),
		RemoteIP:            requestRemoteIP(r.RemoteAddr),
		UserAgent:           r.UserAgent(),
	})
	if err != nil {
		h.redirectOAuthError(w, r, "oauth_failed")
		return
	}

	h.setSessionCookie(w, result.Session.Token, result.Session.ExpiresAt)
	http.Redirect(w, r, h.webBaseURL, http.StatusFound)
}

func (h *AuthHandler) Me(w http.ResponseWriter, r *http.Request) {
	authSession, ok := appmiddleware.AuthUserFromContext(r.Context())
	if !ok {
		apierror.WriteError(w, apierror.New(http.StatusUnauthorized, "UNAUTHORIZED", "authentication required", nil))
		return
	}

	_ = apierror.WriteJSON(w, http.StatusOK, apierror.DataEnvelope[authResultResponse]{
		Data: authResultResponse{User: toUserResponse(authSession)},
	})
}

func (h *AuthHandler) UpdateMe(w http.ResponseWriter, r *http.Request) {
	authSession, ok := appmiddleware.AuthUserFromContext(r.Context())
	if !ok {
		apierror.WriteError(w, apierror.New(http.StatusUnauthorized, "UNAUTHORIZED", "authentication required", nil))
		return
	}

	var req updateProfileRequest
	if err := decodeRequestBody(w, r, &req); err != nil {
		writeInvalidRequest(w, err)
		return
	}

	if err := h.validator.Struct(req); err != nil {
		writeValidationError(w, err)
		return
	}

	var avatarMetadata *json.RawMessage
	if req.AvatarMetadata != nil {
		avatarMetadata = &req.AvatarMetadata
	}

	updatedUser, err := h.authService.UpdateProfile(r.Context(), service.UpdateProfileInput{
		UserID:         authSession.ID,
		DisplayName:    req.DisplayName,
		AvatarMetadata: avatarMetadata,
	})
	if err != nil {
		switch {
		case errors.Is(err, service.ErrInvalidProfileUpdateInput):
			writeInvalidRequest(w, err)
		case errors.Is(err, service.ErrDisplayNameAlreadyInUse):
			writeConflict(w, "DISPLAY_NAME_ALREADY_IN_USE", "display name is already in use", err)
		case errors.Is(err, service.ErrInvalidSession):
			apierror.WriteError(w, apierror.New(http.StatusUnauthorized, "UNAUTHORIZED", "authentication required", err))
		default:
			writeInternalError(w, err)
		}
		return
	}

	_ = apierror.WriteJSON(w, http.StatusOK, apierror.DataEnvelope[authResultResponse]{
		Data: authResultResponse{User: toUserResponse(updatedUser)},
	})
}

func (h *AuthHandler) CreateAvatarUploadURL(w http.ResponseWriter, r *http.Request) {
	authSession, ok := appmiddleware.AuthUserFromContext(r.Context())
	if !ok {
		apierror.WriteError(w, apierror.New(http.StatusUnauthorized, "UNAUTHORIZED", "authentication required", nil))
		return
	}

	var req avatarUploadURLRequest
	if err := decodeRequestBody(w, r, &req); err != nil {
		writeInvalidRequest(w, err)
		return
	}

	if err := h.validator.Struct(req); err != nil {
		writeValidationError(w, err)
		return
	}

	result, err := h.authService.CreateAvatarUploadURL(r.Context(), service.CreateAvatarUploadURLInput{
		UserID:        authSession.ID,
		ContentType:   req.ContentType,
		ContentLength: req.ContentLength,
	})
	if err != nil {
		switch {
		case errors.Is(err, service.ErrInvalidSession):
			apierror.WriteError(w, apierror.New(http.StatusUnauthorized, "UNAUTHORIZED", "authentication required", err))
		case errors.Is(err, service.ErrAvatarStorageUnavailable):
			apierror.WriteError(w, apierror.New(http.StatusServiceUnavailable, "AVATAR_STORAGE_UNAVAILABLE", "avatar storage unavailable", err))
		case errors.Is(err, service.ErrAvatarFileTooLarge):
			apierror.WriteError(w, apierror.New(http.StatusBadRequest, "AVATAR_FILE_TOO_LARGE", "avatar file too large", err))
		case errors.Is(err, service.ErrUnsupportedAvatarContentType):
			apierror.WriteError(w, apierror.New(http.StatusBadRequest, "UNSUPPORTED_AVATAR_CONTENT_TYPE", "unsupported avatar content type", err))
		case errors.Is(err, service.ErrInvalidAvatarUploadInput):
			writeInvalidRequest(w, err)
		default:
			writeInternalError(w, err)
		}
		return
	}

	_ = apierror.WriteJSON(w, http.StatusOK, apierror.DataEnvelope[avatarUploadURLResponse]{
		Data: avatarUploadURLResponse{
			UploadURL: result.UploadURL,
			Method:    result.Method,
			ObjectKey: result.ObjectKey,
			ExpiresAt: result.ExpiresAt,
			Headers:   result.Headers,
		},
	})
}

func (h *AuthHandler) ConfirmAvatarUpload(w http.ResponseWriter, r *http.Request) {
	authSession, ok := appmiddleware.AuthUserFromContext(r.Context())
	if !ok {
		apierror.WriteError(w, apierror.New(http.StatusUnauthorized, "UNAUTHORIZED", "authentication required", nil))
		return
	}

	var req confirmAvatarUploadRequest
	if err := decodeRequestBody(w, r, &req); err != nil {
		writeInvalidRequest(w, err)
		return
	}

	if err := h.validator.Struct(req); err != nil {
		writeValidationError(w, err)
		return
	}

	updatedUser, err := h.authService.ConfirmAvatarUpload(r.Context(), service.ConfirmAvatarUploadInput{
		UserID:    authSession.ID,
		ObjectKey: req.ObjectKey,
	})
	if err != nil {
		switch {
		case errors.Is(err, service.ErrInvalidSession):
			apierror.WriteError(w, apierror.New(http.StatusUnauthorized, "UNAUTHORIZED", "authentication required", err))
		case errors.Is(err, service.ErrAvatarStorageUnavailable):
			apierror.WriteError(w, apierror.New(http.StatusServiceUnavailable, "AVATAR_STORAGE_UNAVAILABLE", "avatar storage unavailable", err))
		case errors.Is(err, service.ErrAvatarObjectNotFound):
			apierror.WriteError(w, apierror.New(http.StatusBadRequest, "AVATAR_OBJECT_NOT_FOUND", "avatar object not found", err))
		case errors.Is(err, service.ErrAvatarFileTooLarge):
			apierror.WriteError(w, apierror.New(http.StatusBadRequest, "AVATAR_FILE_TOO_LARGE", "avatar file too large", err))
		case errors.Is(err, service.ErrUnsupportedAvatarContentType):
			apierror.WriteError(w, apierror.New(http.StatusBadRequest, "UNSUPPORTED_AVATAR_CONTENT_TYPE", "unsupported avatar content type", err))
		case errors.Is(err, service.ErrInvalidAvatarFileContent):
			apierror.WriteError(w, apierror.New(http.StatusBadRequest, "INVALID_AVATAR_FILE_CONTENT", "avatar file content is invalid", err))
		case errors.Is(err, service.ErrInvalidAvatarUploadInput), errors.Is(err, service.ErrInvalidProfileUpdateInput):
			writeInvalidRequest(w, err)
		default:
			writeInternalError(w, err)
		}
		return
	}

	_ = apierror.WriteJSON(w, http.StatusOK, apierror.DataEnvelope[authResultResponse]{
		Data: authResultResponse{User: toUserResponse(updatedUser)},
	})
}

func (h *AuthHandler) DeleteAvatar(w http.ResponseWriter, r *http.Request) {
	authSession, ok := appmiddleware.AuthUserFromContext(r.Context())
	if !ok {
		apierror.WriteError(w, apierror.New(http.StatusUnauthorized, "UNAUTHORIZED", "authentication required", nil))
		return
	}

	updatedUser, err := h.authService.DeleteAvatar(r.Context(), authSession.ID)
	if err != nil {
		switch {
		case errors.Is(err, service.ErrInvalidSession):
			apierror.WriteError(w, apierror.New(http.StatusUnauthorized, "UNAUTHORIZED", "authentication required", err))
		case errors.Is(err, service.ErrAvatarStorageUnavailable):
			apierror.WriteError(w, apierror.New(http.StatusServiceUnavailable, "AVATAR_STORAGE_UNAVAILABLE", "avatar storage unavailable", err))
		case errors.Is(err, service.ErrInvalidAvatarUploadInput):
			writeInvalidRequest(w, err)
		default:
			writeInternalError(w, err)
		}
		return
	}

	_ = apierror.WriteJSON(w, http.StatusOK, apierror.DataEnvelope[authResultResponse]{
		Data: authResultResponse{User: toUserResponse(updatedUser)},
	})
}

func (h *AuthHandler) currentSessionToken(r *http.Request) string {
	sessionCookie, err := r.Cookie(h.sessionCookie.Name)
	if err != nil {
		return ""
	}

	return sessionCookie.Value
}

func (h *AuthHandler) setSessionCookie(w http.ResponseWriter, token string, expiresAt time.Time) {
	maxAge := int(h.sessionCookie.TTL.Seconds())
	if maxAge <= 0 {
		maxAge = int(time.Until(expiresAt).Seconds())
	}

	if maxAge < 1 {
		maxAge = 1
	}

	http.SetCookie(w, &http.Cookie{
		Name:     h.sessionCookie.Name,
		Value:    token,
		Path:     "/",
		Domain:   h.sessionCookie.Domain,
		Expires:  expiresAt,
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   h.sessionCookie.Secure,
		SameSite: parseSameSite(h.sessionCookie.SameSite),
	})
}

func (h *AuthHandler) clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     h.sessionCookie.Name,
		Value:    "",
		Path:     "/",
		Domain:   h.sessionCookie.Domain,
		Expires:  time.Unix(0, 0).UTC(),
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   h.sessionCookie.Secure,
		SameSite: parseSameSite(h.sessionCookie.SameSite),
	})
}

func (h *AuthHandler) setOAuthStateCookie(w http.ResponseWriter, state string) {
	http.SetCookie(w, &http.Cookie{
		Name:     oauthStateCookieName,
		Value:    state,
		Path:     "/v1/auth/oauth/github/callback",
		Domain:   h.sessionCookie.Domain,
		Expires:  time.Now().UTC().Add(h.oauthStateTTL),
		MaxAge:   int(h.oauthStateTTL.Seconds()),
		HttpOnly: true,
		Secure:   h.sessionCookie.Secure,
		SameSite: parseSameSite(h.sessionCookie.SameSite),
	})
}

func (h *AuthHandler) clearOAuthStateCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     oauthStateCookieName,
		Value:    "",
		Path:     "/v1/auth/oauth/github/callback",
		Domain:   h.sessionCookie.Domain,
		Expires:  time.Unix(0, 0).UTC(),
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   h.sessionCookie.Secure,
		SameSite: parseSameSite(h.sessionCookie.SameSite),
	})
}

func (h *AuthHandler) validateOAuthState(r *http.Request, state string) bool {
	if strings.TrimSpace(state) == "" {
		return false
	}

	cookie, err := r.Cookie(oauthStateCookieName)
	if err != nil {
		return false
	}

	if strings.TrimSpace(cookie.Value) == "" {
		return false
	}

	return subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(state)) == 1
}

func (h *AuthHandler) generateOAuthState() (string, error) {
	state, _, err := auth.GenerateEmailToken()
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

func parseSameSite(value string) http.SameSite {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "strict":
		return http.SameSiteStrictMode
	case "none":
		return http.SameSiteNoneMode
	default:
		return http.SameSiteLaxMode
	}
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
			fields[toJSONField(validationError.Field())] = validationError.Tag()
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

func writeInternalError(w http.ResponseWriter, err error) {
	apierror.WriteError(w, apierror.New(http.StatusInternalServerError, "INTERNAL_ERROR", "internal server error", err))
}

func toJSONField(field string) string {
	switch field {
	case "Email":
		return "email"
	case "Password":
		return "password"
	case "DisplayName":
		return "display_name"
	case "Token":
		return "token"
	case "ContentType":
		return "content_type"
	case "ContentLength":
		return "content_length"
	case "ObjectKey":
		return "object_key"
	default:
		return strings.ToLower(field)
	}
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
