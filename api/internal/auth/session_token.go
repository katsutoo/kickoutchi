package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
)

const authTokenSizeBytes = 32

func GenerateSessionToken() (string, []byte, error) {
	token, hash, err := generateToken()
	if err != nil {
		return "", nil, fmt.Errorf("generate session token: %w", err)
	}

	return token, hash, nil
}

func HashSessionToken(token string) []byte {
	return hashToken(token)
}

func GenerateEmailToken() (string, []byte, error) {
	token, hash, err := generateToken()
	if err != nil {
		return "", nil, fmt.Errorf("generate email token: %w", err)
	}

	return token, hash, nil
}

func GenerateOAuthState() (string, []byte, error) {
	token, hash, err := generateToken()
	if err != nil {
		return "", nil, fmt.Errorf("generate oauth state: %w", err)
	}

	return token, hash, nil
}

func HashEmailToken(token string) []byte {
	return hashToken(token)
}

func generateToken() (string, []byte, error) {
	buffer := make([]byte, authTokenSizeBytes)
	if _, err := rand.Read(buffer); err != nil {
		return "", nil, err
	}

	token := base64.RawURLEncoding.EncodeToString(buffer)
	return token, hashToken(token), nil
}

func hashToken(token string) []byte {
	hash := sha256.Sum256([]byte(token))
	return hash[:]
}
