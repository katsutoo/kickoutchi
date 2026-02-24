package repository

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
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

	trimmed := bytes.TrimSpace(value)
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
