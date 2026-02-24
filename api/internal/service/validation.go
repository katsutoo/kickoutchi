package service

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
)

var validDisplayNameRegexp = regexp.MustCompile(`^[\p{L}\p{N}_\- ]+$`)

func normalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

func clampString(value string, maxLen int) string {
	trimmed := strings.TrimSpace(value)
	if maxLen <= 0 {
		return ""
	}

	if utf8.RuneCountInString(trimmed) <= maxLen {
		return trimmed
	}

	runes := []rune(trimmed)
	return string(runes[:maxLen])
}

func isPasswordWithinBounds(password string) bool {
	length := len(password)
	return length >= minPasswordLen && length <= maxPasswordLen
}

func shouldRefreshSession(now, expiresAt time.Time, refreshWindow time.Duration) bool {
	if refreshWindow <= 0 {
		return false
	}

	return now.Add(refreshWindow).After(expiresAt)
}

func validateDisplayName(displayName string) (string, error) {
	trimmed := strings.TrimSpace(displayName)
	if len(trimmed) < minDisplayNameLength || len(trimmed) > maxDisplayNameLength {
		return "", errors.New("display name length is invalid")
	}

	if !validDisplayNameRegexp.MatchString(trimmed) {
		return "", errors.New("display name contains invalid characters")
	}

	return trimmed, nil
}

func normalizeAvatarMetadata(raw json.RawMessage) (json.RawMessage, error) {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" {
		return json.RawMessage("{}"), nil
	}

	if len(trimmed) > maxAvatarMetadataBytes {
		return nil, errors.New("avatar metadata is too large")
	}

	var decoded map[string]any
	if err := json.Unmarshal([]byte(trimmed), &decoded); err != nil {
		return nil, errors.New("avatar metadata must be a valid JSON object")
	}

	normalized, err := json.Marshal(decoded)
	if err != nil {
		return nil, fmt.Errorf("normalize avatar metadata: %w", err)
	}

	return json.RawMessage(normalized), nil
}

func normalizeAvatarContentType(contentType string) (string, string, error) {
	trimmed := strings.ToLower(strings.TrimSpace(contentType))
	if trimmed == "" {
		return "", "", ErrInvalidAvatarUploadInput
	}

	if mediaType, _, found := strings.Cut(trimmed, ";"); found {
		trimmed = strings.TrimSpace(mediaType)
	}

	switch trimmed {
	case "image/jpeg", "image/jpg":
		return "image/jpeg", ".jpg", nil
	case "image/png":
		return "image/png", ".png", nil
	case "image/webp":
		return "image/webp", ".webp", nil
	default:
		return "", "", ErrUnsupportedAvatarContentType
	}
}

func validateAvatarMagicBytes(contentType string, prefix []byte) error {
	if len(prefix) == 0 {
		return ErrInvalidAvatarFileContent
	}

	switch contentType {
	case "image/jpeg":
		if hasJPEGSignature(prefix) {
			return nil
		}
	case "image/png":
		if hasPNGSignature(prefix) {
			return nil
		}
	case "image/webp":
		if hasWebPSignature(prefix) {
			return nil
		}
	default:
		return ErrUnsupportedAvatarContentType
	}

	return ErrInvalidAvatarFileContent
}

func hasJPEGSignature(data []byte) bool {
	return len(data) >= 3 &&
		data[0] == 0xFF &&
		data[1] == 0xD8 &&
		data[2] == 0xFF
}

func hasPNGSignature(data []byte) bool {
	if len(data) < 8 {
		return false
	}

	pngSignature := []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}
	for index, b := range pngSignature {
		if data[index] != b {
			return false
		}
	}

	return true
}

func hasWebPSignature(data []byte) bool {
	if len(data) < 12 {
		return false
	}

	return string(data[0:4]) == "RIFF" && string(data[8:12]) == "WEBP"
}

func newAvatarObjectKey(userID uuid.UUID, extension string) (string, error) {
	avatarID, err := uuid.NewV7()
	if err != nil {
		return "", err
	}

	trimmedExtension := strings.TrimSpace(extension)
	if trimmedExtension == "" {
		trimmedExtension = ".bin"
	}

	return fmt.Sprintf("users/%s/avatars/%s%s", userID.String(), avatarID.String(), trimmedExtension), nil
}

func normalizeAvatarObjectKey(objectKey string) (string, error) {
	trimmed := strings.Trim(strings.TrimSpace(objectKey), "/")
	if trimmed == "" {
		return "", errors.New("object key is required")
	}

	if strings.Contains(trimmed, "..") {
		return "", errors.New("object key contains invalid path segments")
	}

	return trimmed, nil
}

func isOwnedAvatarObjectKey(userID uuid.UUID, objectKey string) bool {
	prefix := fmt.Sprintf("users/%s/avatars/", userID.String())
	return strings.HasPrefix(objectKey, prefix)
}

func avatarObjectKeyFromMetadata(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}

	var metadata map[string]any
	if err := json.Unmarshal(raw, &metadata); err != nil {
		return ""
	}

	value, ok := metadata["key"]
	if !ok {
		return ""
	}

	key, ok := value.(string)
	if !ok {
		return ""
	}

	normalizedKey, err := normalizeAvatarObjectKey(key)
	if err != nil {
		return ""
	}

	return normalizedKey
}

func cloneJSON(raw json.RawMessage) json.RawMessage {
	if len(raw) == 0 {
		return json.RawMessage("{}")
	}

	cloned := make([]byte, len(raw))
	copy(cloned, raw)
	return json.RawMessage(cloned)
}
