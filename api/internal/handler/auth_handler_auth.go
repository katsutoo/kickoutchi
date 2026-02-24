package handler

import (
	"errors"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/katsutoo/kickoutchi/api/internal/apierror"
	"github.com/katsutoo/kickoutchi/api/internal/apiresponse"
	appmiddleware "github.com/katsutoo/kickoutchi/api/internal/middleware"
	"github.com/katsutoo/kickoutchi/api/internal/service"
)

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
			h.writeInternalServerError(r, w, err)
		}
		return
	}

	h.setSessionCookie(w, result.Session.Token, result.Session.ExpiresAt)

	_ = apiresponse.WriteJSON(w, http.StatusCreated, apiresponse.DataEnvelope[authResultResponse]{
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
			h.writeInternalServerError(r, w, err)
		}
		return
	}

	h.setSessionCookie(w, result.Session.Token, result.Session.ExpiresAt)

	_ = apiresponse.WriteJSON(w, http.StatusOK, apiresponse.DataEnvelope[authResultResponse]{
		Data: authResultResponse{User: toUserResponse(result.User)},
	})
}

func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	if err := h.authService.Logout(r.Context(), h.currentSessionToken(r)); err != nil {
		h.writeInternalServerError(r, w, err)
		return
	}

	h.clearSessionCookie(w)

	_ = apiresponse.WriteJSON(w, http.StatusOK, apiresponse.DataEnvelope[actionStatusResponse]{
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
			h.writeInternalServerError(r, w, err)
		}
		return
	}

	_ = apiresponse.WriteJSON(w, http.StatusOK, apiresponse.DataEnvelope[actionStatusResponse]{
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
			h.writeInternalServerError(r, w, err)
		}
		return
	}

	_ = apiresponse.WriteJSON(w, http.StatusOK, apiresponse.DataEnvelope[actionStatusResponse]{
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
			h.writeInternalServerError(r, w, err)
		}
		return
	}

	_ = apiresponse.WriteJSON(w, http.StatusOK, apiresponse.DataEnvelope[actionStatusResponse]{
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
			h.writeInternalServerError(r, w, err)
		}
		return
	}

	_ = apiresponse.WriteJSON(w, http.StatusOK, apiresponse.DataEnvelope[actionStatusResponse]{
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
		h.writeInternalServerError(r, w, err)
		return
	}

	authorizationURL, err := h.authService.GitHubAuthorizationURL(state)
	if err != nil {
		switch {
		case errors.Is(err, service.ErrOAuthUnavailable):
			apierror.WriteError(w, apierror.New(http.StatusServiceUnavailable, "OAUTH_UNAVAILABLE", "oauth provider unavailable", err))
		default:
			h.writeInternalServerError(r, w, err)
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
