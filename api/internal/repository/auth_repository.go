package repository

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/katsutoo/kickoutchi/api/internal/database"
	"github.com/katsutoo/kickoutchi/api/internal/database/sqlc"
)

var (
	ErrEmailAlreadyExists       = errors.New("email already exists")
	ErrDisplayNameAlreadyExists = errors.New("display name already exists")
	ErrUserNotFound             = errors.New("user not found")
	ErrSessionNotFound          = errors.New("session not found")
	ErrInvalidEmailToken        = errors.New("invalid or expired email token")
	ErrOAuthIdentityNotFound    = errors.New("oauth identity not found")
	ErrOAuthProviderLinked      = errors.New("oauth provider already linked")
)

const (
	EmailTokenTypeEmailVerification = "email_verification"
	EmailTokenTypePasswordReset     = "password_reset"

	OAuthProviderGitHub = "github"
	OAuthProviderGoogle = "google"
	OAuthProviderX      = "x"
)

var defaultAvatarMetadata = []byte("{}")

type User struct {
	ID              uuid.UUID
	Email           string
	PasswordHash    string
	DisplayName     string
	Role            string
	EmailVerifiedAt *time.Time
	AvatarMetadata  json.RawMessage
	InsertedAt      time.Time
	UpdatedAt       time.Time
}

type Session struct {
	ID         uuid.UUID
	UserID     uuid.UUID
	TokenHash  []byte
	ExpiresAt  time.Time
	IPAddress  string
	UserAgent  string
	InsertedAt time.Time
}

type EmailToken struct {
	ID         uuid.UUID
	UserID     uuid.UUID
	TokenHash  []byte
	Type       string
	ExpiresAt  time.Time
	UsedAt     *time.Time
	InsertedAt time.Time
}

type OAuthIdentity struct {
	ID            uuid.UUID
	UserID        uuid.UUID
	Provider      string
	ProviderUID   string
	ProviderEmail string
	InsertedAt    time.Time
}

type CreateUserParams struct {
	ID             uuid.UUID
	Email          string
	PasswordHash   string
	DisplayName    string
	Role           string
	AvatarMetadata json.RawMessage
}

type RegisterParams struct {
	UserID           uuid.UUID
	Email            string
	PasswordHash     string
	DisplayName      string
	Role             string
	SessionID        uuid.UUID
	SessionTokenHash []byte
	SessionExpiresAt time.Time
	IPAddress        string
	UserAgent        string
}

type RegisterResult struct {
	User    User
	Session Session
}

type IssueEmailTokenParams struct {
	UserID    uuid.UUID
	Type      string
	TokenHash []byte
	ExpiresAt time.Time
}

type ResetPasswordByTokenParams struct {
	TokenHash       []byte
	NewPasswordHash string
}

type RotateSessionParams struct {
	SessionID         uuid.UUID
	UserID            uuid.UUID
	TokenHash         []byte
	ExpiresAt         time.Time
	IPAddress         string
	UserAgent         string
	PreviousTokenHash []byte
}

type CreateOAuthIdentityParams struct {
	ID            uuid.UUID
	UserID        uuid.UUID
	Provider      string
	ProviderUID   string
	ProviderEmail string
}

type UpdateUserProfileParams struct {
	UserID         uuid.UUID
	DisplayName    string
	AvatarMetadata json.RawMessage
}

type AuthRepository struct {
	db      *database.DB
	queries *sqlc.Queries
}

func NewAuthRepository(db *database.DB) *AuthRepository {
	return &AuthRepository{
		db:      db,
		queries: sqlc.New(db.Pool()),
	}
}

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

func (r *AuthRepository) GetOAuthIdentityByProviderUID(ctx context.Context, provider, providerUID string) (OAuthIdentity, error) {
	storedIdentity, err := r.queries.GetOAuthIdentityByProviderUID(ctx, sqlc.GetOAuthIdentityByProviderUIDParams{
		Provider:    provider,
		ProviderUid: providerUID,
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return OAuthIdentity{}, ErrOAuthIdentityNotFound
		}

		return OAuthIdentity{}, fmt.Errorf("get oauth identity by provider uid: %w", err)
	}

	identity, err := fromSQLCOAuthIdentity(storedIdentity)
	if err != nil {
		return OAuthIdentity{}, fmt.Errorf("map oauth identity by provider uid: %w", err)
	}

	return identity, nil
}

func (r *AuthRepository) CreateOAuthIdentity(ctx context.Context, params CreateOAuthIdentityParams) (OAuthIdentity, error) {
	createdIdentity, err := r.queries.CreateOAuthIdentity(ctx, sqlc.CreateOAuthIdentityParams{
		ID:            toPgUUID(params.ID),
		UserID:        toPgUUID(params.UserID),
		Provider:      params.Provider,
		ProviderUid:   params.ProviderUID,
		ProviderEmail: params.ProviderEmail,
	})
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			if pgErr.ConstraintName == "oauth_identities_user_provider_unique_idx" {
				return OAuthIdentity{}, ErrOAuthProviderLinked
			}
		}

		return OAuthIdentity{}, fmt.Errorf("create oauth identity: %w", err)
	}

	identity, err := fromSQLCOAuthIdentity(createdIdentity)
	if err != nil {
		return OAuthIdentity{}, fmt.Errorf("map created oauth identity: %w", err)
	}

	return identity, nil
}

func mapCreateUserError(err error) error {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		switch pgErr.ConstraintName {
		case "users_email_unique_idx":
			return fmt.Errorf("%w: %v", ErrEmailAlreadyExists, err)
		case "users_display_name_unique_idx":
			return fmt.Errorf("%w: %v", ErrDisplayNameAlreadyExists, err)
		}
	}

	return fmt.Errorf("create user: %w", err)
}

func fromSQLCUser(user sqlc.User) (User, error) {
	userID, err := fromPgUUID(user.ID)
	if err != nil {
		return User{}, err
	}

	insertedAt, err := fromPgTimestamptz(user.InsertedAt)
	if err != nil {
		return User{}, err
	}

	updatedAt, err := fromPgTimestamptz(user.UpdatedAt)
	if err != nil {
		return User{}, err
	}

	emailVerifiedAt, err := fromPgOptionalTimestamptz(user.EmailVerifiedAt)
	if err != nil {
		return User{}, err
	}

	avatarMetadata := sanitizeAvatarMetadata(user.AvatarMetadata)

	return User{
		ID:              userID,
		Email:           user.Email,
		PasswordHash:    user.PasswordHash,
		DisplayName:     user.DisplayName,
		Role:            user.Role,
		EmailVerifiedAt: emailVerifiedAt,
		AvatarMetadata:  cloneJSONRawMessage(avatarMetadata),
		InsertedAt:      insertedAt,
		UpdatedAt:       updatedAt,
	}, nil
}

func fromSQLCSession(session sqlc.Session) (Session, error) {
	sessionID, err := fromPgUUID(session.ID)
	if err != nil {
		return Session{}, err
	}

	userID, err := fromPgUUID(session.UserID)
	if err != nil {
		return Session{}, err
	}

	expiresAt, err := fromPgTimestamptz(session.ExpiresAt)
	if err != nil {
		return Session{}, err
	}

	insertedAt, err := fromPgTimestamptz(session.InsertedAt)
	if err != nil {
		return Session{}, err
	}

	return Session{
		ID:         sessionID,
		UserID:     userID,
		TokenHash:  cloneBytes(session.TokenHash),
		ExpiresAt:  expiresAt,
		IPAddress:  fromPgText(session.IpAddress),
		UserAgent:  fromPgText(session.UserAgent),
		InsertedAt: insertedAt,
	}, nil
}

func fromSQLCEmailToken(emailToken sqlc.EmailToken) (EmailToken, error) {
	emailTokenID, err := fromPgUUID(emailToken.ID)
	if err != nil {
		return EmailToken{}, err
	}

	userID, err := fromPgUUID(emailToken.UserID)
	if err != nil {
		return EmailToken{}, err
	}

	expiresAt, err := fromPgTimestamptz(emailToken.ExpiresAt)
	if err != nil {
		return EmailToken{}, err
	}

	insertedAt, err := fromPgTimestamptz(emailToken.InsertedAt)
	if err != nil {
		return EmailToken{}, err
	}

	usedAt, err := fromPgOptionalTimestamptz(emailToken.UsedAt)
	if err != nil {
		return EmailToken{}, err
	}

	return EmailToken{
		ID:         emailTokenID,
		UserID:     userID,
		TokenHash:  cloneBytes(emailToken.TokenHash),
		Type:       emailToken.Type,
		ExpiresAt:  expiresAt,
		UsedAt:     usedAt,
		InsertedAt: insertedAt,
	}, nil
}

func fromSQLCOAuthIdentity(identity sqlc.OauthIdentity) (OAuthIdentity, error) {
	identityID, err := fromPgUUID(identity.ID)
	if err != nil {
		return OAuthIdentity{}, err
	}

	userID, err := fromPgUUID(identity.UserID)
	if err != nil {
		return OAuthIdentity{}, err
	}

	insertedAt, err := fromPgTimestamptz(identity.InsertedAt)
	if err != nil {
		return OAuthIdentity{}, err
	}

	return OAuthIdentity{
		ID:            identityID,
		UserID:        userID,
		Provider:      identity.Provider,
		ProviderUID:   identity.ProviderUid,
		ProviderEmail: identity.ProviderEmail,
		InsertedAt:    insertedAt,
	}, nil
}

func toPgUUID(value uuid.UUID) pgtype.UUID {
	return pgtype.UUID{Bytes: value, Valid: true}
}

func toPgTimestamptz(value time.Time) pgtype.Timestamptz {
	return pgtype.Timestamptz{Time: value.UTC(), Valid: true}
}

func toPgText(value string) pgtype.Text {
	if value == "" {
		return pgtype.Text{}
	}

	return pgtype.Text{String: value, Valid: true}
}

func fromPgUUID(value pgtype.UUID) (uuid.UUID, error) {
	if !value.Valid {
		return uuid.Nil, errors.New("null UUID")
	}

	return uuid.UUID(value.Bytes), nil
}

func fromPgTimestamptz(value pgtype.Timestamptz) (time.Time, error) {
	if !value.Valid {
		return time.Time{}, errors.New("null timestamptz")
	}

	return value.Time.UTC(), nil
}

func fromPgOptionalTimestamptz(value pgtype.Timestamptz) (*time.Time, error) {
	if !value.Valid {
		return nil, nil
	}

	timestamp := value.Time.UTC()
	return &timestamp, nil
}

func fromPgText(value pgtype.Text) string {
	if !value.Valid {
		return ""
	}

	return value.String
}

func isSupportedEmailTokenType(value string) bool {
	switch value {
	case EmailTokenTypeEmailVerification, EmailTokenTypePasswordReset:
		return true
	default:
		return false
	}
}

func sanitizeAvatarMetadata(value []byte) []byte {
	if len(value) == 0 {
		return cloneBytes(defaultAvatarMetadata)
	}

	trimmed := bytesTrimSpace(value)
	if len(trimmed) == 0 {
		return cloneBytes(defaultAvatarMetadata)
	}

	return cloneBytes(trimmed)
}

func cloneBytes(value []byte) []byte {
	if len(value) == 0 {
		return nil
	}

	cloned := make([]byte, len(value))
	copy(cloned, value)
	return cloned
}

func cloneJSONRawMessage(value []byte) json.RawMessage {
	if len(value) == 0 {
		return json.RawMessage(defaultAvatarMetadata)
	}

	cloned := make([]byte, len(value))
	copy(cloned, value)
	return json.RawMessage(cloned)
}

func bytesTrimSpace(value []byte) []byte {
	start := 0
	for start < len(value) && isWhitespace(value[start]) {
		start++
	}

	end := len(value)
	for end > start && isWhitespace(value[end-1]) {
		end--
	}

	return value[start:end]
}

func isWhitespace(value byte) bool {
	return value == ' ' || value == '\n' || value == '\r' || value == '\t'
}
