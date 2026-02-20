package service

import (
	"errors"
	"testing"
)

func TestValidateAvatarMagicBytes(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name        string
		contentType string
		prefix      []byte
		expectedErr error
	}{
		{
			name:        "jpeg valid",
			contentType: "image/jpeg",
			prefix:      []byte{0xFF, 0xD8, 0xFF, 0xE0},
		},
		{
			name:        "jpeg invalid",
			contentType: "image/jpeg",
			prefix:      []byte{0x89, 0x50, 0x4E},
			expectedErr: ErrInvalidAvatarFileContent,
		},
		{
			name:        "png valid",
			contentType: "image/png",
			prefix:      []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00},
		},
		{
			name:        "webp valid",
			contentType: "image/webp",
			prefix:      []byte{'R', 'I', 'F', 'F', 0x2A, 0x00, 0x00, 0x00, 'W', 'E', 'B', 'P'},
		},
		{
			name:        "webp invalid",
			contentType: "image/webp",
			prefix:      []byte{'R', 'I', 'F', 'F', 0x2A, 0x00, 0x00, 0x00, 'P', 'N', 'G', ' '},
			expectedErr: ErrInvalidAvatarFileContent,
		},
		{
			name:        "unsupported content type",
			contentType: "image/gif",
			prefix:      []byte{'G', 'I', 'F', '8'},
			expectedErr: ErrUnsupportedAvatarContentType,
		},
		{
			name:        "empty prefix",
			contentType: "image/png",
			prefix:      nil,
			expectedErr: ErrInvalidAvatarFileContent,
		},
	}

	for _, testCase := range testCases {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			err := validateAvatarMagicBytes(testCase.contentType, testCase.prefix)
			if testCase.expectedErr == nil {
				if err != nil {
					t.Fatalf("validateAvatarMagicBytes() returned unexpected error: %v", err)
				}
				return
			}

			if !errors.Is(err, testCase.expectedErr) {
				t.Fatalf("validateAvatarMagicBytes() error = %v, expected %v", err, testCase.expectedErr)
			}
		})
	}
}
