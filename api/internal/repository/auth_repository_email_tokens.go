package repository

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/katsutoo/kickoutchi/api/internal/database/sqlc"
)

func (r *AuthRepository) IssueEmailToken(ctx context.Context, params IssueEmailTokenParams) (EmailToken, error) {
	if !isSupportedEmailTokenType(params.Type) {
		return EmailToken{}, errors.New("unsupported email token type")
	}

	if len(params.TokenHash) == 0 {
		return EmailToken{}, errors.New("email token hash is required")
	}

	if params.ExpiresAt.IsZero() {
		return EmailToken{}, errors.New("email token expiration is required")
	}

	tx, err := r.db.Pool().BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return EmailToken{}, fmt.Errorf("begin issue email token transaction: %w", err)
	}
	defer func() {
		_ = tx.Rollback(ctx)
	}()

	queries := r.queries.WithTx(tx)

	if _, err := queries.LockUserByID(ctx, toPgUUID(params.UserID)); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return EmailToken{}, ErrUserNotFound
		}

		return EmailToken{}, fmt.Errorf("lock user for email token issue: %w", err)
	}

	if err := queries.InvalidateActiveEmailTokensByUserAndType(ctx, sqlc.InvalidateActiveEmailTokensByUserAndTypeParams{
		UserID: toPgUUID(params.UserID),
		Type:   params.Type,
	}); err != nil {
		return EmailToken{}, fmt.Errorf("invalidate active email tokens: %w", err)
	}

	emailTokenID, err := uuid.NewV7()
	if err != nil {
		return EmailToken{}, fmt.Errorf("generate email token id: %w", err)
	}

	createdEmailToken, err := queries.CreateEmailToken(ctx, sqlc.CreateEmailTokenParams{
		ID:        toPgUUID(emailTokenID),
		UserID:    toPgUUID(params.UserID),
		TokenHash: params.TokenHash,
		Type:      params.Type,
		ExpiresAt: toPgTimestamptz(params.ExpiresAt),
	})
	if err != nil {
		return EmailToken{}, fmt.Errorf("create email token: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return EmailToken{}, fmt.Errorf("commit issue email token transaction: %w", err)
	}

	emailToken, err := fromSQLCEmailToken(createdEmailToken)
	if err != nil {
		return EmailToken{}, fmt.Errorf("map created email token: %w", err)
	}

	return emailToken, nil
}

func (r *AuthRepository) VerifyEmailByToken(ctx context.Context, tokenHash []byte) (User, error) {
	if len(tokenHash) == 0 {
		return User{}, ErrInvalidEmailToken
	}

	tx, err := r.db.Pool().BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return User{}, fmt.Errorf("begin verify email transaction: %w", err)
	}
	defer func() {
		_ = tx.Rollback(ctx)
	}()

	queries := r.queries.WithTx(tx)

	emailToken, err := queries.GetEmailTokenByHashActiveType(ctx, sqlc.GetEmailTokenByHashActiveTypeParams{
		TokenHash: tokenHash,
		Type:      EmailTokenTypeEmailVerification,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return User{}, ErrInvalidEmailToken
		}

		return User{}, fmt.Errorf("get active verification token: %w", err)
	}

	if _, err := queries.MarkEmailTokenUsed(ctx, emailToken.ID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return User{}, ErrInvalidEmailToken
		}

		return User{}, fmt.Errorf("mark verification token used: %w", err)
	}

	verifiedUser, err := queries.MarkUserEmailVerified(ctx, emailToken.UserID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return User{}, ErrUserNotFound
		}

		return User{}, fmt.Errorf("mark user email verified: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return User{}, fmt.Errorf("commit verify email transaction: %w", err)
	}

	user, err := fromSQLCUser(verifiedUser)
	if err != nil {
		return User{}, fmt.Errorf("map verified user: %w", err)
	}

	return user, nil
}

func (r *AuthRepository) ResetPasswordByToken(ctx context.Context, params ResetPasswordByTokenParams) error {
	if len(params.TokenHash) == 0 {
		return errors.New("email token hash is required")
	}

	if params.NewPasswordHash == "" {
		return errors.New("new password hash is required")
	}

	tx, err := r.db.Pool().BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("begin reset password transaction: %w", err)
	}
	defer func() {
		_ = tx.Rollback(ctx)
	}()

	queries := r.queries.WithTx(tx)

	emailToken, err := queries.GetEmailTokenByHashActiveType(ctx, sqlc.GetEmailTokenByHashActiveTypeParams{
		TokenHash: params.TokenHash,
		Type:      EmailTokenTypePasswordReset,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrInvalidEmailToken
		}

		return fmt.Errorf("get active password reset token: %w", err)
	}

	if _, err := queries.MarkEmailTokenUsed(ctx, emailToken.ID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrInvalidEmailToken
		}

		return fmt.Errorf("mark reset token used: %w", err)
	}

	if _, err := queries.UpdateUserPasswordHash(ctx, sqlc.UpdateUserPasswordHashParams{
		ID:           emailToken.UserID,
		PasswordHash: params.NewPasswordHash,
	}); err != nil {
		return fmt.Errorf("update password hash: %w", err)
	}

	if err := queries.DeleteSessionsByUserID(ctx, emailToken.UserID); err != nil {
		return fmt.Errorf("delete sessions by user id: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit reset password transaction: %w", err)
	}

	return nil
}
