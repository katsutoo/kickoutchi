//go:build integration
// +build integration

package integration

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/katsutoo/kickoutchi/api/internal/auth"
	"github.com/katsutoo/kickoutchi/api/internal/repository"
	"github.com/katsutoo/kickoutchi/api/test/testutil"
)

func TestAuthRepositoryCreateUserUniqueConstraints(t *testing.T) {
	db := testutil.NewDatabase(t)
	repo := repository.NewAuthRepository(db)

	firstUser := createRepositoryTestUser(t, repo, uniqueEmail("repo_first"), uniqueDisplayName("repo_first"))
	if firstUser.ID == uuid.Nil {
		t.Fatalf("expected created user id to be set")
	}

	_, err := repo.CreateUser(t.Context(), repository.CreateUserParams{
		ID:             mustUUIDv7(t),
		Email:          firstUser.Email,
		PasswordHash:   mustHashPassword(t, "AnotherPass1!"),
		DisplayName:    uniqueDisplayName("repo_second"),
		Role:           "user",
		AvatarMetadata: json.RawMessage("{}"),
	})
	if !errors.Is(err, repository.ErrEmailAlreadyExists) {
		t.Fatalf("expected ErrEmailAlreadyExists, got: %v", err)
	}

	_, err = repo.CreateUser(t.Context(), repository.CreateUserParams{
		ID:             mustUUIDv7(t),
		Email:          uniqueEmail("repo_third"),
		PasswordHash:   mustHashPassword(t, "AnotherPass2!"),
		DisplayName:    firstUser.DisplayName,
		Role:           "user",
		AvatarMetadata: json.RawMessage("{}"),
	})
	if !errors.Is(err, repository.ErrDisplayNameAlreadyExists) {
		t.Fatalf("expected ErrDisplayNameAlreadyExists, got: %v", err)
	}
}

func TestAuthRepositoryIssueEmailTokenInvalidatesPreviousActiveToken(t *testing.T) {
	db := testutil.NewDatabase(t)
	repo := repository.NewAuthRepository(db)

	user := createRepositoryTestUser(t, repo, uniqueEmail("repo_token"), uniqueDisplayName("repo_token"))

	_, err := repo.IssueEmailToken(t.Context(), repository.IssueEmailTokenParams{
		UserID:    user.ID,
		Type:      repository.EmailTokenTypeEmailVerification,
		TokenHash: []byte("first_verification_hash"),
		ExpiresAt: time.Now().UTC().Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("issue first email token: %v", err)
	}

	_, err = repo.IssueEmailToken(t.Context(), repository.IssueEmailTokenParams{
		UserID:    user.ID,
		Type:      repository.EmailTokenTypeEmailVerification,
		TokenHash: []byte("second_verification_hash"),
		ExpiresAt: time.Now().UTC().Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("issue second email token: %v", err)
	}

	_, err = repo.VerifyEmailByToken(t.Context(), []byte("first_verification_hash"))
	if !errors.Is(err, repository.ErrInvalidEmailToken) {
		t.Fatalf("expected first token to be invalidated, got: %v", err)
	}

	verifiedUser, err := repo.VerifyEmailByToken(t.Context(), []byte("second_verification_hash"))
	if err != nil {
		t.Fatalf("verify second token: %v", err)
	}

	if verifiedUser.EmailVerifiedAt == nil {
		t.Fatalf("expected verified user to have email_verified_at set")
	}

	_, err = repo.VerifyEmailByToken(t.Context(), []byte("second_verification_hash"))
	if !errors.Is(err, repository.ErrInvalidEmailToken) {
		t.Fatalf("expected second token to be one-time use, got: %v", err)
	}
}

func TestAuthRepositoryCreateOAuthIdentityUpsertAndUniqueProviderLink(t *testing.T) {
	db := testutil.NewDatabase(t)
	repo := repository.NewAuthRepository(db)

	firstUser := createRepositoryTestUser(t, repo, uniqueEmail("oauth_first"), uniqueDisplayName("oauth_first"))
	secondUser := createRepositoryTestUser(t, repo, uniqueEmail("oauth_second"), uniqueDisplayName("oauth_second"))

	_, err := repo.CreateOAuthIdentity(t.Context(), repository.CreateOAuthIdentityParams{
		ID:            mustUUIDv7(t),
		UserID:        firstUser.ID,
		Provider:      repository.OAuthProviderGitHub,
		ProviderUID:   "github_uid_123",
		ProviderEmail: "first@example.com",
	})
	if err != nil {
		t.Fatalf("create first oauth identity: %v", err)
	}

	updatedIdentity, err := repo.CreateOAuthIdentity(t.Context(), repository.CreateOAuthIdentityParams{
		ID:            mustUUIDv7(t),
		UserID:        secondUser.ID,
		Provider:      repository.OAuthProviderGitHub,
		ProviderUID:   "github_uid_123",
		ProviderEmail: "updated@example.com",
	})
	if err != nil {
		t.Fatalf("upsert oauth identity by provider uid: %v", err)
	}

	if updatedIdentity.UserID != firstUser.ID {
		t.Fatalf("expected provider uid upsert to keep original user id %s, got %s", firstUser.ID, updatedIdentity.UserID)
	}

	if updatedIdentity.ProviderEmail != "updated@example.com" {
		t.Fatalf("expected provider email to be updated, got %q", updatedIdentity.ProviderEmail)
	}

	_, err = repo.CreateOAuthIdentity(t.Context(), repository.CreateOAuthIdentityParams{
		ID:            mustUUIDv7(t),
		UserID:        firstUser.ID,
		Provider:      repository.OAuthProviderGitHub,
		ProviderUID:   "github_uid_456",
		ProviderEmail: "second-link@example.com",
	})
	if !errors.Is(err, repository.ErrOAuthProviderLinked) {
		t.Fatalf("expected ErrOAuthProviderLinked for duplicate user/provider link, got: %v", err)
	}
}

func createRepositoryTestUser(t *testing.T, repo *repository.AuthRepository, email, displayName string) repository.User {
	t.Helper()

	createdUser, err := repo.CreateUser(t.Context(), repository.CreateUserParams{
		ID:             mustUUIDv7(t),
		Email:          email,
		PasswordHash:   mustHashPassword(t, "Str0ngPassw0rd!"),
		DisplayName:    displayName,
		Role:           "user",
		AvatarMetadata: json.RawMessage("{}"),
	})
	if err != nil {
		t.Fatalf("create repository test user: %v", err)
	}

	return createdUser
}

func mustUUIDv7(t *testing.T) uuid.UUID {
	t.Helper()

	id, err := uuid.NewV7()
	if err != nil {
		t.Fatalf("generate uuidv7: %v", err)
	}

	return id
}

func mustHashPassword(t *testing.T, password string) string {
	t.Helper()

	hasher := auth.NewArgon2Hasher(auth.Argon2Params{
		Memory:     1024,
		Time:       1,
		Threads:    1,
		KeyLength:  32,
		SaltLength: 16,
	})

	hash, err := hasher.Hash(password)
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}

	return hash
}
