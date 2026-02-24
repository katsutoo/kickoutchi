package handler

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/katsutoo/kickoutchi/api/internal/apierror"
	"github.com/katsutoo/kickoutchi/api/internal/apiresponse"
	appmiddleware "github.com/katsutoo/kickoutchi/api/internal/middleware"
	"github.com/katsutoo/kickoutchi/api/internal/service"
)

func (h *AuthHandler) Me(w http.ResponseWriter, r *http.Request) {
	authSession, ok := appmiddleware.AuthUserFromContext(r.Context())
	if !ok {
		apierror.WriteError(w, apierror.New(http.StatusUnauthorized, "UNAUTHORIZED", "authentication required", nil))
		return
	}

	_ = apiresponse.WriteJSON(w, http.StatusOK, apiresponse.DataEnvelope[authResultResponse]{
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
			h.writeInternalServerError(r, w, err)
		}
		return
	}

	_ = apiresponse.WriteJSON(w, http.StatusOK, apiresponse.DataEnvelope[authResultResponse]{
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
			h.writeInternalServerError(r, w, err)
		}
		return
	}

	_ = apiresponse.WriteJSON(w, http.StatusOK, apiresponse.DataEnvelope[avatarUploadURLResponse]{
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
			h.writeInternalServerError(r, w, err)
		}
		return
	}

	_ = apiresponse.WriteJSON(w, http.StatusOK, apiresponse.DataEnvelope[authResultResponse]{
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
			h.writeInternalServerError(r, w, err)
		}
		return
	}

	_ = apiresponse.WriteJSON(w, http.StatusOK, apiresponse.DataEnvelope[authResultResponse]{
		Data: authResultResponse{User: toUserResponse(updatedUser)},
	})
}
