package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/katsutoo/kickoutchi/api/internal/client"
	"github.com/katsutoo/kickoutchi/api/internal/repository"
)

func (s *AuthService) UpdateProfile(ctx context.Context, input UpdateProfileInput) (UserView, error) {
	if input.UserID == uuid.Nil {
		return UserView{}, ErrInvalidSession
	}

	if input.DisplayName == nil && input.AvatarMetadata == nil {
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

	updatedAvatarMetadata := user.AvatarMetadata
	if input.AvatarMetadata != nil {
		avatarMetadata, err := normalizeAvatarMetadata(*input.AvatarMetadata)
		if err != nil {
			return UserView{}, ErrInvalidProfileUpdateInput
		}
		updatedAvatarMetadata = avatarMetadata
	}

	updatedUser, err := s.authRepository.UpdateUserProfile(ctx, repository.UpdateUserProfileParams{
		UserID:         user.ID,
		DisplayName:    updatedDisplayName,
		AvatarMetadata: updatedAvatarMetadata,
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

	presignedUpload, err := s.avatarStorage.CreatePresignedUploadURL(ctx, objectKey, normalizedContentType)
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
		return UserView{}, ErrUnsupportedAvatarContentType
	}

	if avatarObject.ContentLength <= 0 {
		return UserView{}, ErrInvalidAvatarUploadInput
	}

	if avatarObject.ContentLength > maxAvatarUploadBytes {
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
			return UserView{}, ErrInvalidAvatarFileContent
		}

		return UserView{}, fmt.Errorf("validate avatar object content: %w", err)
	}

	user, err := s.authRepository.GetUserByID(ctx, input.UserID)
	if err != nil {
		if errors.Is(err, repository.ErrUserNotFound) {
			return UserView{}, ErrInvalidSession
		}

		return UserView{}, fmt.Errorf("get user for avatar confirm: %w", err)
	}

	avatarMetadata := map[string]any{
		"provider":     "r2",
		"key":          objectKey,
		"url":          s.avatarStorage.PublicURL(objectKey),
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
			return UserView{}, ErrDisplayNameAlreadyInUse
		case errors.Is(err, repository.ErrUserNotFound):
			return UserView{}, ErrInvalidSession
		default:
			return UserView{}, fmt.Errorf("update avatar metadata: %w", err)
		}
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
