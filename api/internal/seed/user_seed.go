package seed

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/google/uuid"

	"github.com/katsutoo/kickoutchi/api/internal/repository"
)

const (
	minSeedPasswordLen = 8
	maxSeedPasswordLen = 128
)

type User struct {
	Email       string
	DisplayName string
	Role        string
}

type Result struct {
	Created  int
	Existing int
}

type passwordHasher interface {
	Hash(password string) (string, error)
}

type userRepository interface {
	GetUserByEmail(ctx context.Context, email string) (repository.User, error)
	CreateUser(ctx context.Context, params repository.CreateUserParams) (repository.User, error)
}

var defaultUsers = []User{
	{
		Email:       "local-user@kickoutchi.dev",
		DisplayName: "local_user",
		Role:        "user",
	},
	{
		Email:       "local-admin@kickoutchi.dev",
		DisplayName: "local_admin",
		Role:        "admin",
	},
}

func DefaultUsers() []User {
	seedUsers := make([]User, len(defaultUsers))
	copy(seedUsers, defaultUsers)
	return seedUsers
}

func SeedUsers(
	ctx context.Context,
	repo userRepository,
	hasher passwordHasher,
	password string,
	users []User,
	logger *slog.Logger,
) (Result, error) {
	if repo == nil {
		return Result{}, errors.New("seed user repository is required")
	}

	if hasher == nil {
		return Result{}, errors.New("seed password hasher is required")
	}

	if logger == nil {
		logger = slog.Default()
	}

	if err := validateSeedPassword(password); err != nil {
		return Result{}, err
	}

	result := Result{}

	for index, candidate := range users {
		seedUser, err := normalizeSeedUser(candidate)
		if err != nil {
			return result, fmt.Errorf("normalize seed user at index %d: %w", index, err)
		}

		_, err = repo.GetUserByEmail(ctx, seedUser.Email)
		if err == nil {
			result.Existing++
			logger.Info(
				"seed_user_exists",
				slog.String("email", seedUser.Email),
				slog.String("display_name", seedUser.DisplayName),
				slog.String("role", seedUser.Role),
			)
			continue
		}

		if !errors.Is(err, repository.ErrUserNotFound) {
			return result, fmt.Errorf("lookup seed user by email %s: %w", seedUser.Email, err)
		}

		passwordHash, err := hasher.Hash(password)
		if err != nil {
			return result, fmt.Errorf("hash seed password for %s: %w", seedUser.Email, err)
		}

		userID, err := uuid.NewV7()
		if err != nil {
			return result, fmt.Errorf("generate seed user id for %s: %w", seedUser.Email, err)
		}

		createdUser, err := repo.CreateUser(ctx, repository.CreateUserParams{
			ID:             userID,
			Email:          seedUser.Email,
			PasswordHash:   passwordHash,
			DisplayName:    seedUser.DisplayName,
			Role:           seedUser.Role,
			AvatarMetadata: json.RawMessage("{}"),
		})
		if err != nil {
			switch {
			case errors.Is(err, repository.ErrEmailAlreadyExists):
				result.Existing++
				logger.Info(
					"seed_user_exists",
					slog.String("email", seedUser.Email),
					slog.String("display_name", seedUser.DisplayName),
					slog.String("role", seedUser.Role),
				)
				continue
			case errors.Is(err, repository.ErrDisplayNameAlreadyExists):
				return result, fmt.Errorf("seed display name conflict for %s: %w", seedUser.DisplayName, err)
			default:
				return result, fmt.Errorf("create seed user %s: %w", seedUser.Email, err)
			}
		}

		result.Created++
		logger.Info(
			"seed_user_created",
			slog.String("user_id", createdUser.ID.String()),
			slog.String("email", createdUser.Email),
			slog.String("display_name", createdUser.DisplayName),
			slog.String("role", createdUser.Role),
		)
	}

	return result, nil
}

func normalizeSeedUser(user User) (User, error) {
	email := strings.ToLower(strings.TrimSpace(user.Email))
	if email == "" {
		return User{}, errors.New("email is required")
	}

	displayName := strings.TrimSpace(user.DisplayName)
	if displayName == "" {
		return User{}, errors.New("display name is required")
	}

	role := strings.ToLower(strings.TrimSpace(user.Role))
	if role == "" {
		role = "user"
	}

	switch role {
	case "user", "moderator", "admin":
	default:
		return User{}, fmt.Errorf("unsupported role %q", role)
	}

	return User{
		Email:       email,
		DisplayName: displayName,
		Role:        role,
	}, nil
}

func validateSeedPassword(password string) error {
	length := len(strings.TrimSpace(password))
	if length < minSeedPasswordLen || length > maxSeedPasswordLen {
		return fmt.Errorf("seed password must be between %d and %d characters", minSeedPasswordLen, maxSeedPasswordLen)
	}

	return nil
}
