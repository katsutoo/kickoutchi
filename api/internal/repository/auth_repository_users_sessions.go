package repository

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/katsutoo/kickoutchi/api/internal/database/sqlc"
)

func (r *AuthRepository) CreateUser(ctx context.Context, params CreateUserParams) (User, error) {
	avatarMetadata := sanitizeAvatarMetadata(params.AvatarMetadata)

	createdUser, err := r.queries.CreateUser(ctx, sqlc.CreateUserParams{
		ID:             toPgUUID(params.ID),
		Email:          params.Email,
		PasswordHash:   params.PasswordHash,
		DisplayName:    params.DisplayName,
		Role:           params.Role,
		AvatarMetadata: avatarMetadata,
	})
	if err != nil {
		return User{}, mapCreateUserError(err)
	}

	user, err := fromSQLCUser(createdUser)
	if err != nil {
		return User{}, fmt.Errorf("map created user: %w", err)
	}

	return user, nil
}

func (r *AuthRepository) GetUserByEmail(ctx context.Context, email string) (User, error) {
	storedUser, err := r.queries.GetUserByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return User{}, ErrUserNotFound
		}

		return User{}, fmt.Errorf("get user by email: %w", err)
	}

	user, err := fromSQLCUser(storedUser)
	if err != nil {
		return User{}, fmt.Errorf("map user by email: %w", err)
	}

	return user, nil
}

func (r *AuthRepository) GetUserByID(ctx context.Context, userID uuid.UUID) (User, error) {
	storedUser, err := r.queries.GetUserByID(ctx, toPgUUID(userID))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return User{}, ErrUserNotFound
		}

		return User{}, fmt.Errorf("get user by id: %w", err)
	}

	user, err := fromSQLCUser(storedUser)
	if err != nil {
		return User{}, fmt.Errorf("map user by id: %w", err)
	}

	return user, nil
}

func (r *AuthRepository) UpdateUserProfile(ctx context.Context, params UpdateUserProfileParams) (User, error) {
	updatedUser, err := r.queries.UpdateUserProfile(ctx, sqlc.UpdateUserProfileParams{
		ID:             toPgUUID(params.UserID),
		DisplayName:    params.DisplayName,
		AvatarMetadata: sanitizeAvatarMetadata(params.AvatarMetadata),
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return User{}, ErrUserNotFound
		}

		if mappedError := mapCreateUserError(err); !errors.Is(mappedError, err) {
			return User{}, mappedError
		}

		return User{}, fmt.Errorf("update user profile: %w", err)
	}

	user, err := fromSQLCUser(updatedUser)
	if err != nil {
		return User{}, fmt.Errorf("map updated user profile: %w", err)
	}

	return user, nil
}

func (r *AuthRepository) CreateUserAndSession(ctx context.Context, params RegisterParams) (RegisterResult, error) {
	tx, err := r.db.Pool().BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return RegisterResult{}, fmt.Errorf("begin register transaction: %w", err)
	}
	defer func() {
		_ = tx.Rollback(ctx)
	}()

	queries := r.queries.WithTx(tx)

	createdUser, err := queries.CreateUser(ctx, sqlc.CreateUserParams{
		ID:             toPgUUID(params.UserID),
		Email:          params.Email,
		PasswordHash:   params.PasswordHash,
		DisplayName:    params.DisplayName,
		Role:           params.Role,
		AvatarMetadata: defaultAvatarMetadata,
	})
	if err != nil {
		return RegisterResult{}, mapCreateUserError(err)
	}

	createdSession, err := queries.CreateSession(ctx, sqlc.CreateSessionParams{
		ID:        toPgUUID(params.SessionID),
		UserID:    toPgUUID(params.UserID),
		TokenHash: params.SessionTokenHash,
		ExpiresAt: toPgTimestamptz(params.SessionExpiresAt),
		IpAddress: toPgText(params.IPAddress),
		UserAgent: toPgText(params.UserAgent),
	})
	if err != nil {
		return RegisterResult{}, fmt.Errorf("create session: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return RegisterResult{}, fmt.Errorf("commit register transaction: %w", err)
	}

	user, err := fromSQLCUser(createdUser)
	if err != nil {
		return RegisterResult{}, fmt.Errorf("map created user: %w", err)
	}

	session, err := fromSQLCSession(createdSession)
	if err != nil {
		return RegisterResult{}, fmt.Errorf("map created session: %w", err)
	}

	return RegisterResult{User: user, Session: session}, nil
}

func (r *AuthRepository) RotateSession(ctx context.Context, params RotateSessionParams) (Session, error) {
	if len(params.TokenHash) == 0 {
		return Session{}, errors.New("session token hash is required")
	}

	if params.ExpiresAt.IsZero() {
		return Session{}, errors.New("session expiration is required")
	}

	tx, err := r.db.Pool().BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return Session{}, fmt.Errorf("begin rotate session transaction: %w", err)
	}
	defer func() {
		_ = tx.Rollback(ctx)
	}()

	queries := r.queries.WithTx(tx)

	if len(params.PreviousTokenHash) > 0 {
		if err := queries.DeleteSessionByTokenHash(ctx, params.PreviousTokenHash); err != nil {
			return Session{}, fmt.Errorf("delete previous session by token hash: %w", err)
		}
	}

	createdSession, err := queries.CreateSession(ctx, sqlc.CreateSessionParams{
		ID:        toPgUUID(params.SessionID),
		UserID:    toPgUUID(params.UserID),
		TokenHash: params.TokenHash,
		ExpiresAt: toPgTimestamptz(params.ExpiresAt),
		IpAddress: toPgText(params.IPAddress),
		UserAgent: toPgText(params.UserAgent),
	})
	if err != nil {
		return Session{}, fmt.Errorf("create rotated session: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return Session{}, fmt.Errorf("commit rotate session transaction: %w", err)
	}

	session, err := fromSQLCSession(createdSession)
	if err != nil {
		return Session{}, fmt.Errorf("map rotated session: %w", err)
	}

	return session, nil
}

func (r *AuthRepository) GetSessionByTokenHashActive(ctx context.Context, tokenHash []byte) (Session, error) {
	storedSession, err := r.queries.GetSessionByTokenHashActive(ctx, tokenHash)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Session{}, ErrSessionNotFound
		}

		return Session{}, fmt.Errorf("get active session by token hash: %w", err)
	}

	session, err := fromSQLCSession(storedSession)
	if err != nil {
		return Session{}, fmt.Errorf("map active session: %w", err)
	}

	return session, nil
}

func (r *AuthRepository) RefreshSessionExpiry(ctx context.Context, sessionID uuid.UUID, expiresAt time.Time) (Session, error) {
	storedSession, err := r.queries.UpdateSessionExpiresAt(ctx, sqlc.UpdateSessionExpiresAtParams{
		ID:        toPgUUID(sessionID),
		ExpiresAt: toPgTimestamptz(expiresAt),
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Session{}, ErrSessionNotFound
		}

		return Session{}, fmt.Errorf("refresh session expiry: %w", err)
	}

	session, err := fromSQLCSession(storedSession)
	if err != nil {
		return Session{}, fmt.Errorf("map refreshed session: %w", err)
	}

	return session, nil
}

func (r *AuthRepository) DeleteSessionByTokenHash(ctx context.Context, tokenHash []byte) error {
	if len(tokenHash) == 0 {
		return nil
	}

	if err := r.queries.DeleteSessionByTokenHash(ctx, tokenHash); err != nil {
		return fmt.Errorf("delete session by token hash: %w", err)
	}

	return nil
}
