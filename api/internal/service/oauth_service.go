package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"unicode"

	"github.com/google/uuid"

	"github.com/katsutoo/kickoutchi/api/internal/auth"
	"github.com/katsutoo/kickoutchi/api/internal/client"
	"github.com/katsutoo/kickoutchi/api/internal/repository"
)

func (s *AuthService) GitHubAuthorizationURL(state string) (string, error) {
	if s.githubOAuthClient == nil {
		return "", ErrOAuthUnavailable
	}

	trimmedState := strings.TrimSpace(state)
	if trimmedState == "" {
		return "", ErrInvalidOAuthCode
	}

	return s.githubOAuthClient.AuthorizationURL(trimmedState), nil
}

func (s *AuthService) LoginWithOAuth(ctx context.Context, input OAuthLoginInput) (LoginResult, error) {
	if s.githubOAuthClient == nil {
		return LoginResult{}, ErrOAuthUnavailable
	}

	provider := strings.ToLower(strings.TrimSpace(input.Provider))
	if provider != repository.OAuthProviderGitHub {
		return LoginResult{}, ErrInvalidOAuthProvider
	}

	code := strings.TrimSpace(input.Code)
	if code == "" {
		return LoginResult{}, ErrInvalidOAuthCode
	}

	githubUser, err := s.githubOAuthClient.FetchUser(ctx, code)
	if err != nil {
		return LoginResult{}, fmt.Errorf("fetch github user: %w", ErrInvalidOAuthCode)
	}

	user, err := s.resolveOAuthUser(ctx, provider, githubUser)
	if err != nil {
		return LoginResult{}, err
	}

	rotatedSession, sessionToken, err := s.rotateSessionForUser(ctx, user.ID, input.CurrentSessionToken, input.RemoteIP, input.UserAgent)
	if err != nil {
		return LoginResult{}, err
	}

	return LoginResult{
		User:    toUserView(user),
		Session: SessionView{Token: sessionToken, ExpiresAt: rotatedSession.ExpiresAt},
	}, nil
}

func (s *AuthService) resolveOAuthUser(ctx context.Context, provider string, oauthUser client.GitHubOAuthUser) (repository.User, error) {
	identity, err := s.authRepository.GetOAuthIdentityByProviderUID(ctx, provider, oauthUser.ProviderUID)
	if err == nil {
		user, err := s.authRepository.GetUserByID(ctx, identity.UserID)
		if err != nil {
			return repository.User{}, fmt.Errorf("get oauth user by identity: %w", err)
		}

		return user, nil
	}

	if !errors.Is(err, repository.ErrOAuthIdentityNotFound) {
		return repository.User{}, fmt.Errorf("lookup oauth identity: %w", err)
	}

	var user repository.User
	user, err = s.authRepository.GetUserByEmail(ctx, normalizeEmail(oauthUser.Email))
	if err != nil {
		if !errors.Is(err, repository.ErrUserNotFound) {
			return repository.User{}, fmt.Errorf("get user by oauth email: %w", err)
		}

		user, err = s.createOAuthUser(ctx, oauthUser)
		if err != nil {
			return repository.User{}, err
		}
	}

	identityID, err := uuid.NewV7()
	if err != nil {
		return repository.User{}, fmt.Errorf("generate oauth identity id: %w", err)
	}

	createdIdentity, err := s.authRepository.CreateOAuthIdentity(ctx, repository.CreateOAuthIdentityParams{
		ID:            identityID,
		UserID:        user.ID,
		Provider:      provider,
		ProviderUID:   oauthUser.ProviderUID,
		ProviderEmail: normalizeEmail(oauthUser.Email),
	})
	if err != nil {
		if errors.Is(err, repository.ErrOAuthProviderLinked) {
			return repository.User{}, fmt.Errorf("create oauth identity: %w", err)
		}

		return repository.User{}, fmt.Errorf("create oauth identity: %w", err)
	}

	if createdIdentity.UserID != user.ID {
		resolvedUser, err := s.authRepository.GetUserByID(ctx, createdIdentity.UserID)
		if err != nil {
			return repository.User{}, fmt.Errorf("resolve oauth identity user: %w", err)
		}

		return resolvedUser, nil
	}

	return user, nil
}

func (s *AuthService) createOAuthUser(ctx context.Context, oauthUser client.GitHubOAuthUser) (repository.User, error) {
	randomSecret, _, err := auth.GenerateEmailToken()
	if err != nil {
		return repository.User{}, fmt.Errorf("generate oauth password seed: %w", err)
	}

	passwordHash, err := s.passwordHasher.Hash(randomSecret)
	if err != nil {
		return repository.User{}, fmt.Errorf("hash oauth password seed: %w", err)
	}

	baseDisplayName := deriveOAuthDisplayName(oauthUser)

	for attempt := 0; attempt < 20; attempt++ {
		displayName := baseDisplayName
		if attempt > 0 {
			suffix := strings.ReplaceAll(uuid.NewString(), "-", "")[:6]
			displayName = clampString(baseDisplayName, maxDisplayNameLength-7) + "_" + suffix
		}

		userID, err := uuid.NewV7()
		if err != nil {
			return repository.User{}, fmt.Errorf("generate oauth user id: %w", err)
		}

		createdUser, err := s.authRepository.CreateUser(ctx, repository.CreateUserParams{
			ID:             userID,
			Email:          normalizeEmail(oauthUser.Email),
			PasswordHash:   passwordHash,
			DisplayName:    displayName,
			Role:           defaultUserRole,
			AvatarMetadata: json.RawMessage("{}"),
		})
		if err != nil {
			switch {
			case errors.Is(err, repository.ErrDisplayNameAlreadyExists):
				continue
			case errors.Is(err, repository.ErrEmailAlreadyExists):
				existingUser, lookupErr := s.authRepository.GetUserByEmail(ctx, normalizeEmail(oauthUser.Email))
				if lookupErr != nil {
					return repository.User{}, fmt.Errorf("resolve oauth email conflict user: %w", lookupErr)
				}
				return existingUser, nil
			default:
				return repository.User{}, fmt.Errorf("create oauth user: %w", err)
			}
		}

		return createdUser, nil
	}

	return repository.User{}, errors.New("unable to create oauth user with unique display name")
}

func deriveOAuthDisplayName(user client.GitHubOAuthUser) string {
	candidate := strings.TrimSpace(user.Login)
	if candidate == "" {
		candidate = strings.TrimSpace(user.Name)
	}

	if candidate == "" {
		parts := strings.SplitN(normalizeEmail(user.Email), "@", 2)
		candidate = parts[0]
	}

	if candidate == "" {
		candidate = "user"
	}

	cleaned := strings.Map(func(r rune) rune {
		switch {
		case unicode.IsLetter(r), unicode.IsDigit(r):
			return unicode.ToLower(r)
		case r == '_' || r == '-' || r == ' ':
			return '_'
		default:
			return -1
		}
	}, candidate)

	cleaned = strings.Trim(cleaned, "_")
	if cleaned == "" {
		cleaned = "user"
	}

	if len(cleaned) < minDisplayNameLength {
		cleaned = cleaned + strings.Repeat("x", minDisplayNameLength-len(cleaned))
	}

	return clampString(cleaned, maxDisplayNameLength)
}
