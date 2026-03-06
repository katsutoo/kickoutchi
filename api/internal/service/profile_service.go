package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"

	"github.com/katsutoo/kickoutchi/api/internal/client"
	"github.com/katsutoo/kickoutchi/api/internal/repository"
)

func (s *AuthService) UpdateProfile(ctx context.Context, input UpdateProfileInput) (UserView, error) {
	if input.UserID == uuid.Nil {
		return UserView{}, ErrInvalidSession
	}

	if input.DisplayName == nil {
		return UserView{}, ErrInvalidProfileUpdateInput
	}

	user, err := s.authRepository.GetUserByID(ctx, input.UserID)
	if err != nil {
		if errors.Is(err, repository.ErrUserNotFound) {
			return UserView{}, ErrInvalidSession
		}

		return UserView{}, fmt.Errorf("get user for profile update: %w", err)
	}

	updatedDisplayName := user.DisplayName
	if input.DisplayName != nil {
		displayName, err := validateDisplayName(*input.DisplayName)
		if err != nil {
			return UserView{}, ErrInvalidProfileUpdateInput
		}
		updatedDisplayName = displayName
	}

	updatedUser, err := s.authRepository.UpdateUserProfile(ctx, repository.UpdateUserProfileParams{
		UserID:         user.ID,
		DisplayName:    updatedDisplayName,
		AvatarMetadata: user.AvatarMetadata,
	})
	if err != nil {
		switch {
		case errors.Is(err, repository.ErrDisplayNameAlreadyExists):
			return UserView{}, ErrDisplayNameAlreadyInUse
		case errors.Is(err, repository.ErrUserNotFound):
			return UserView{}, ErrInvalidSession
		default:
			return UserView{}, fmt.Errorf("update user profile: %w", err)
		}
	}

	return toUserView(updatedUser), nil
}

func (s *AuthService) CreateAvatarUploadURL(ctx context.Context, input CreateAvatarUploadURLInput) (CreateAvatarUploadURLResult, error) {
	if input.UserID == uuid.Nil {
		return CreateAvatarUploadURLResult{}, ErrInvalidSession
	}

	if s.avatarStorage == nil {
		return CreateAvatarUploadURLResult{}, ErrAvatarStorageUnavailable
	}

	normalizedContentType, fileExtension, err := normalizeAvatarContentType(input.ContentType)
	if err != nil {
		return CreateAvatarUploadURLResult{}, err
	}

	if input.ContentLength <= 0 {
		return CreateAvatarUploadURLResult{}, ErrInvalidAvatarUploadInput
	}

	if input.ContentLength > maxAvatarUploadBytes {
		return CreateAvatarUploadURLResult{}, ErrAvatarFileTooLarge
	}

	objectKey, err := newAvatarObjectKey(input.UserID, fileExtension)
	if err != nil {
		return CreateAvatarUploadURLResult{}, fmt.Errorf("generate avatar object key: %w", err)
	}

	presignedUpload, err := s.avatarStorage.CreatePresignedUploadURL(ctx, objectKey, normalizedContentType, input.ContentLength)
	if err != nil {
		return CreateAvatarUploadURLResult{}, fmt.Errorf("create avatar upload url: %w", err)
	}

	headers := make(map[string]string, len(presignedUpload.Headers))
	for key, value := range presignedUpload.Headers {
		headers[key] = value
	}

	expiresAt := presignedUpload.ExpiresAt
	if expiresAt.IsZero() {
		expiresAt = time.Now().UTC().Add(s.avatarUploadURLTTL)
	}

	return CreateAvatarUploadURLResult{
		UploadURL: presignedUpload.URL,
		Method:    presignedUpload.Method,
		ObjectKey: presignedUpload.ObjectKey,
		ExpiresAt: expiresAt,
		Headers:   headers,
	}, nil
}

func (s *AuthService) ConfirmAvatarUpload(ctx context.Context, input ConfirmAvatarUploadInput) (UserView, error) {
	if input.UserID == uuid.Nil {
		return UserView{}, ErrInvalidSession
	}

	if s.avatarStorage == nil {
		return UserView{}, ErrAvatarStorageUnavailable
	}

	objectKey, err := normalizeAvatarObjectKey(input.ObjectKey)
	if err != nil {
		return UserView{}, ErrInvalidAvatarUploadInput
	}

	if !isOwnedAvatarObjectKey(input.UserID, objectKey) {
		return UserView{}, ErrInvalidAvatarUploadInput
	}

	avatarObject, err := s.avatarStorage.HeadObject(ctx, objectKey)
	if err != nil {
		if errors.Is(err, client.ErrObjectNotFound) {
			return UserView{}, ErrAvatarObjectNotFound
		}

		return UserView{}, fmt.Errorf("head avatar object: %w", err)
	}

	normalizedContentType, _, err := normalizeAvatarContentType(avatarObject.ContentType)
	if err != nil {
		s.cleanupAvatarObject(ctx, objectKey)
		return UserView{}, ErrUnsupportedAvatarContentType
	}

	if avatarObject.ContentLength <= 0 {
		s.cleanupAvatarObject(ctx, objectKey)
		return UserView{}, ErrInvalidAvatarUploadInput
	}

	if avatarObject.ContentLength > maxAvatarUploadBytes {
		s.cleanupAvatarObject(ctx, objectKey)
		return UserView{}, ErrAvatarFileTooLarge
	}

	avatarPrefix, err := s.avatarStorage.ReadObjectPrefix(ctx, objectKey, avatarMagicBytesReadLimit)
	if err != nil {
		if errors.Is(err, client.ErrObjectNotFound) {
			return UserView{}, ErrAvatarObjectNotFound
		}

		return UserView{}, fmt.Errorf("read avatar object prefix: %w", err)
	}

	if err := validateAvatarMagicBytes(normalizedContentType, avatarPrefix); err != nil {
		if errors.Is(err, ErrInvalidAvatarFileContent) {
			s.cleanupAvatarObject(ctx, objectKey)
			return UserView{}, ErrInvalidAvatarFileContent
		}

		return UserView{}, fmt.Errorf("validate avatar object content: %w", err)
	}

	user, err := s.authRepository.GetUserByID(ctx, input.UserID)
	if err != nil {
		if errors.Is(err, repository.ErrUserNotFound) {
			s.cleanupAvatarObject(ctx, objectKey)
			return UserView{}, ErrInvalidSession
		}

		return UserView{}, fmt.Errorf("get user for avatar confirm: %w", err)
	}

	previousObjectKey := avatarObjectKeyFromMetadata(user.AvatarMetadata)

	avatarMetadata := map[string]any{
		"provider":     "r2",
		"key":          objectKey,
		"content_type": normalizedContentType,
		"size_bytes":   avatarObject.ContentLength,
		"updated_at":   time.Now().UTC().Format(time.RFC3339Nano),
	}

	if avatarObject.ETag != "" {
		avatarMetadata["etag"] = avatarObject.ETag
	}

	if !avatarObject.LastModified.IsZero() {
		avatarMetadata["last_modified"] = avatarObject.LastModified.UTC().Format(time.RFC3339Nano)
	}

	normalizedAvatarMetadata, err := json.Marshal(avatarMetadata)
	if err != nil {
		return UserView{}, fmt.Errorf("marshal avatar metadata: %w", err)
	}

	updatedUser, err := s.authRepository.UpdateUserProfile(ctx, repository.UpdateUserProfileParams{
		UserID:         user.ID,
		DisplayName:    user.DisplayName,
		AvatarMetadata: json.RawMessage(normalizedAvatarMetadata),
	})
	if err != nil {
		switch {
		case errors.Is(err, repository.ErrDisplayNameAlreadyExists):
			s.cleanupAvatarObject(ctx, objectKey)
			return UserView{}, ErrDisplayNameAlreadyInUse
		case errors.Is(err, repository.ErrUserNotFound):
			s.cleanupAvatarObject(ctx, objectKey)
			return UserView{}, ErrInvalidSession
		default:
			s.cleanupAvatarObject(ctx, objectKey)
			return UserView{}, fmt.Errorf("update avatar metadata: %w", err)
		}
	}

	if previousObjectKey != "" && previousObjectKey != objectKey {
		s.cleanupAvatarObject(ctx, previousObjectKey)
	}

	return toUserView(updatedUser), nil
}

func (s *AuthService) DeleteAvatar(ctx context.Context, userID uuid.UUID) (UserView, error) {
	if userID == uuid.Nil {
		return UserView{}, ErrInvalidSession
	}

	user, err := s.authRepository.GetUserByID(ctx, userID)
	if err != nil {
		if errors.Is(err, repository.ErrUserNotFound) {
			return UserView{}, ErrInvalidSession
		}

		return UserView{}, fmt.Errorf("get user for avatar delete: %w", err)
	}

	if s.avatarStorage != nil {
		objectKey := avatarObjectKeyFromMetadata(user.AvatarMetadata)
		if objectKey != "" {
			if err := s.avatarStorage.DeleteObject(ctx, objectKey); err != nil {
				if !errors.Is(err, client.ErrObjectNotFound) {
					return UserView{}, fmt.Errorf("delete avatar object: %w", err)
				}
			}
		}
	}

	updatedUser, err := s.authRepository.UpdateUserProfile(ctx, repository.UpdateUserProfileParams{
		UserID:         user.ID,
		DisplayName:    user.DisplayName,
		AvatarMetadata: json.RawMessage("{}"),
	})
	if err != nil {
		switch {
		case errors.Is(err, repository.ErrDisplayNameAlreadyExists):
			return UserView{}, ErrDisplayNameAlreadyInUse
		case errors.Is(err, repository.ErrUserNotFound):
			return UserView{}, ErrInvalidSession
		default:
			return UserView{}, fmt.Errorf("clear avatar metadata: %w", err)
		}
	}

	return toUserView(updatedUser), nil
}

func (s *AuthService) GetAvatarAccessURL(ctx context.Context, userID uuid.UUID) (AvatarAccessURLResult, error) {
	if userID == uuid.Nil {
		return AvatarAccessURLResult{}, ErrInvalidSession
	}

	if s.avatarStorage == nil {
		return AvatarAccessURLResult{}, ErrAvatarStorageUnavailable
	}

	user, err := s.authRepository.GetUserByID(ctx, userID)
	if err != nil {
		if errors.Is(err, repository.ErrUserNotFound) {
			return AvatarAccessURLResult{}, ErrInvalidSession
		}

		return AvatarAccessURLResult{}, fmt.Errorf("get user for avatar access url: %w", err)
	}

	objectKey := avatarObjectKeyFromMetadata(user.AvatarMetadata)
	if objectKey == "" {
		return AvatarAccessURLResult{}, ErrAvatarNotFound
	}

	if _, err := s.avatarStorage.HeadObject(ctx, objectKey); err != nil {
		if errors.Is(err, client.ErrObjectNotFound) {
			return AvatarAccessURLResult{}, ErrAvatarNotFound
		}

		return AvatarAccessURLResult{}, fmt.Errorf("head avatar object for access url: %w", err)
	}

	presignedRead, err := s.avatarStorage.CreatePresignedReadURL(ctx, objectKey)
	if err != nil {
		return AvatarAccessURLResult{}, fmt.Errorf("create avatar access url: %w", err)
	}

	return AvatarAccessURLResult{
		URL:       presignedRead.URL,
		ExpiresAt: presignedRead.ExpiresAt,
	}, nil
}

func (s *AuthService) cleanupAvatarObject(ctx context.Context, objectKey string) {
	if s.avatarStorage == nil {
		return
	}

	logger := s.loggerForContext(ctx)
	if err := s.avatarStorage.DeleteObject(ctx, objectKey); err != nil && logger != nil && !errors.Is(err, client.ErrObjectNotFound) {
		logger.Warn(
			"avatar_object_cleanup_failed",
			slog.String("object_key", objectKey),
			slog.Any("err", err),
		)
	}
}
