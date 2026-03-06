package auth

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"testing"
)

func TestGenerateSessionTokenProperties(t *testing.T) {
	token, tokenHash, err := GenerateSessionToken()
	if err != nil {
		t.Fatalf("generate session token: %v", err)
	}

	assertGeneratedToken(t, token, tokenHash)
	if !bytes.Equal(HashSessionToken(token), tokenHash) {
		t.Fatal("expected HashSessionToken to match generated token hash")
	}
}

func TestGenerateEmailTokenProperties(t *testing.T) {
	token, tokenHash, err := GenerateEmailToken()
	if err != nil {
		t.Fatalf("generate email token: %v", err)
	}

	assertGeneratedToken(t, token, tokenHash)
	if !bytes.Equal(HashEmailToken(token), tokenHash) {
		t.Fatal("expected HashEmailToken to match generated token hash")
	}
}

func TestGenerateOAuthStateProperties(t *testing.T) {
	state, stateHash, err := GenerateOAuthState()
	if err != nil {
		t.Fatalf("generate oauth state: %v", err)
	}

	assertGeneratedToken(t, state, stateHash)
}

func TestGenerateSessionTokenReturnsDistinctTokens(t *testing.T) {
	firstToken, firstHash, err := GenerateSessionToken()
	if err != nil {
		t.Fatalf("generate first session token: %v", err)
	}

	secondToken, secondHash, err := GenerateSessionToken()
	if err != nil {
		t.Fatalf("generate second session token: %v", err)
	}

	if firstToken == secondToken {
		t.Fatal("expected generated session tokens to differ")
	}

	if bytes.Equal(firstHash, secondHash) {
		t.Fatal("expected generated session token hashes to differ")
	}
}

func TestTokenHashesAreDeterministic(t *testing.T) {
	token := "known-token-value"

	sessionHash := HashSessionToken(token)
	if !bytes.Equal(sessionHash, HashSessionToken(token)) {
		t.Fatal("expected session token hash to be deterministic")
	}

	emailHash := HashEmailToken(token)
	if !bytes.Equal(emailHash, HashEmailToken(token)) {
		t.Fatal("expected email token hash to be deterministic")
	}

	if !bytes.Equal(sessionHash, emailHash) {
		t.Fatal("expected session and email hashing to use the same deterministic digest")
	}

	expected := sha256.Sum256([]byte(token))
	if !bytes.Equal(sessionHash, expected[:]) {
		t.Fatal("expected token hash to equal sha256 digest")
	}
}

func assertGeneratedToken(t *testing.T, token string, tokenHash []byte) {
	t.Helper()

	if token == "" {
		t.Fatal("expected generated token to be non-empty")
	}

	decoded, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		t.Fatalf("decode generated token: %v", err)
	}

	if len(decoded) != authTokenSizeBytes {
		t.Fatalf("unexpected decoded token length: got=%d expected=%d", len(decoded), authTokenSizeBytes)
	}

	if len(tokenHash) != sha256.Size {
		t.Fatalf("unexpected token hash length: got=%d expected=%d", len(tokenHash), sha256.Size)
	}

	expectedHash := sha256.Sum256([]byte(token))
	if !bytes.Equal(tokenHash, expectedHash[:]) {
		t.Fatal("expected generated token hash to match sha256 digest of token")
	}
}
