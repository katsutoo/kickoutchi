package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/katsutoo/kickoutchi/api/internal/auth"
	"github.com/katsutoo/kickoutchi/api/internal/client"
	"github.com/katsutoo/kickoutchi/api/internal/repository"
)

var (
	ErrInvalidRegisterInput              = errors.New("invalid register input")
	ErrInvalidLoginInput                 = errors.New("invalid login input")
	ErrInvalidCredentials                = errors.New("invalid credentials")
	ErrInvalidSession                    = errors.New("invalid or expired session")
	ErrInvalidForgotPasswordInput        = errors.New("invalid forgot password input")
	ErrInvalidResetPasswordInput         = errors.New("invalid reset password input")
	ErrInvalidVerifyEmailInput           = errors.New("invalid verify email input")
	ErrInvalidProfileUpdateInput         = errors.New("invalid profile update input")
	ErrEmailAlreadyInUse                 = errors.New("email already in use")
	ErrDisplayNameAlreadyInUse           = errors.New("display name already in use")
	ErrInvalidOrExpiredResetToken        = errors.New("invalid or expired reset token")
	ErrInvalidOrExpiredVerificationToken = errors.New("invalid or expired verification token")
	ErrOAuthUnavailable                  = errors.New("oauth provider unavailable")
	ErrInvalidOAuthProvider              = errors.New("invalid oauth provider")
	ErrInvalidOAuthCode                  = errors.New("invalid oauth code")
	ErrAvatarStorageUnavailable          = errors.New("avatar storage unavailable")
	ErrInvalidAvatarUploadInput          = errors.New("invalid avatar upload input")
	ErrUnsupportedAvatarContentType      = errors.New("unsupported avatar content type")
	ErrInvalidAvatarFileContent          = errors.New("invalid avatar file content")
	ErrAvatarFileTooLarge                = errors.New("avatar file is too large")
	ErrAvatarObjectNotFound              = errors.New("avatar object not found")
	ErrAvatarNotFound                    = errors.New("avatar not found")
)

const (
	defaultUserRole             = "user"
	defaultSessionRefreshWindow = 24 * time.Hour
	defaultEmailVerificationTTL = 24 * time.Hour
	defaultPasswordResetTTL     = time.Hour
	defaultAvatarUploadURLTTL   = 10 * time.Minute
	minPasswordLen              = 8
	maxPasswordLen              = 128
	maxDisplayNameLength        = 30
	minDisplayNameLength        = 3
	maxAvatarMetadataBytes      = 8 * 1024
	maxAvatarUploadBytes        = 5 * 1024 * 1024
	avatarMagicBytesReadLimit   = 64
)

type AuthService struct {
	authRepository        authRepository
	passwordHasher        passwordHasher
	emailSender           authEmailSender
	githubOAuthClient     githubOAuthClient
	avatarStorage         avatarStorage
	sessionTTL            time.Duration
	sessionRefreshWindow  time.Duration
	passwordResetTokenTTL time.Duration
	emailVerificationTTL  time.Duration
	avatarUploadURLTTL    time.Duration
	logger                *slog.Logger
}

type authRepository interface {
	CreateUserAndSession(ctx context.Context, params repository.RegisterParams) (repository.RegisterResult, error)
	CreateUser(ctx context.Context, params repository.CreateUserParams) (repository.User, error)
	GetUserByEmail(ctx context.Context, email string) (repository.User, error)
	GetUserByID(ctx context.Context, userID uuid.UUID) (repository.User, error)
	MarkUserEmailVerified(ctx context.Context, userID uuid.UUID) (repository.User, error)
	UpdateUserProfile(ctx context.Context, params repository.UpdateUserProfileParams) (repository.User, error)
	RotateSession(ctx context.Context, params repository.RotateSessionParams) (repository.Session, error)
	GetSessionByTokenHashActive(ctx context.Context, tokenHash []byte) (repository.Session, error)
	RefreshSessionExpiry(ctx context.Context, sessionID uuid.UUID, expiresAt time.Time) (repository.Session, error)
	DeleteSessionByTokenHash(ctx context.Context, tokenHash []byte) error
	IssueEmailToken(ctx context.Context, params repository.IssueEmailTokenParams) (repository.EmailToken, error)
	VerifyEmailByToken(ctx context.Context, tokenHash []byte) (repository.User, error)
	ResetPasswordByToken(ctx context.Context, params repository.ResetPasswordByTokenParams) error
	GetOAuthIdentityByProviderUID(ctx context.Context, provider, providerUID string) (repository.OAuthIdentity, error)
	CreateOAuthIdentity(ctx context.Context, params repository.CreateOAuthIdentityParams) (repository.OAuthIdentity, error)
}

type passwordHasher interface {
	Hash(password string) (string, error)
	Verify(password, encodedHash string) (bool, error)
}

type authEmailSender interface {
	SendVerificationEmail(ctx context.Context, toEmail, displayName, token string) error
	SendPasswordResetEmail(ctx context.Context, toEmail, displayName, token string) error
}

type githubOAuthClient interface {
	AuthorizationURL(state string) string
	FetchUser(ctx context.Context, code string) (client.GitHubOAuthUser, error)
}

type avatarStorage interface {
	CreatePresignedUploadURL(ctx context.Context, objectKey, contentType string, contentLength int64) (client.PresignedUpload, error)
	HeadObject(ctx context.Context, objectKey string) (client.ObjectMetadata, error)
	ReadObjectPrefix(ctx context.Context, objectKey string, maxBytes int64) ([]byte, error)
	DeleteObject(ctx context.Context, objectKey string) error
	CreatePresignedReadURL(ctx context.Context, objectKey string) (client.PresignedRead, error)
}

type RegisterInput struct {
	Email       string
	Password    string
	DisplayName string
	RemoteIP    string
	UserAgent   string
}

type LoginInput struct {
	Email               string
	Password            string
	CurrentSessionToken string
	RemoteIP            string
	UserAgent           string
}

type OAuthLoginInput struct {
	Provider            string
	Code                string
	CurrentSessionToken string
	RemoteIP            string
	UserAgent           string
}

type UpdateProfileInput struct {
	UserID      uuid.UUID
	DisplayName *string
}

type CreateAvatarUploadURLInput struct {
	UserID        uuid.UUID
	ContentType   string
	ContentLength int64
}

type CreateAvatarUploadURLResult struct {
	UploadURL string
	Method    string
	ObjectKey string
	ExpiresAt time.Time
	Headers   map[string]string
}

type AvatarAccessURLResult struct {
	URL       string
	ExpiresAt time.Time
}

type ConfirmAvatarUploadInput struct {
	UserID    uuid.UUID
	ObjectKey string
}

type UserView struct {
	ID              uuid.UUID
	Email           string
	DisplayName     string
	Role            string
	EmailVerifiedAt *time.Time
	AvatarMetadata  json.RawMessage
	InsertedAt      time.Time
	UpdatedAt       time.Time
}

type SessionView struct {
	Token     string
	ExpiresAt time.Time
}

type RegisterResult struct {
	User    UserView
	Session SessionView
}

type LoginResult struct {
	User    UserView
	Session SessionView
}

type AuthenticatedSession struct {
	User      UserView
	ExpiresAt time.Time
	Refreshed bool
}

type AuthServiceConfig struct {
	SessionTTL            time.Duration
	SessionRefreshWindow  time.Duration
	PasswordResetTokenTTL time.Duration
	EmailVerificationTTL  time.Duration
	AvatarUploadURLTTL    time.Duration
	Logger                *slog.Logger
}

func NewAuthService(
	authRepository authRepository,
	passwordHasher passwordHasher,
	emailSender authEmailSender,
	githubOAuthClient githubOAuthClient,
	avatarStorage avatarStorage,
	cfg AuthServiceConfig,
) *AuthService {
	if cfg.SessionTTL <= 0 {
		cfg.SessionTTL = 30 * 24 * time.Hour
	}

	if cfg.SessionRefreshWindow <= 0 {
		cfg.SessionRefreshWindow = defaultSessionRefreshWindow
	}

	if cfg.SessionRefreshWindow > cfg.SessionTTL {
		cfg.SessionRefreshWindow = cfg.SessionTTL
	}

	if cfg.PasswordResetTokenTTL <= 0 {
		cfg.PasswordResetTokenTTL = defaultPasswordResetTTL
	}

	if cfg.EmailVerificationTTL <= 0 {
		cfg.EmailVerificationTTL = defaultEmailVerificationTTL
	}

	if cfg.AvatarUploadURLTTL <= 0 {
		cfg.AvatarUploadURLTTL = defaultAvatarUploadURLTTL
	}

	if emailSender == nil {
		emailSender = client.NewNoopAuthEmailSender(nil)
	}

	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}

	return &AuthService{
		authRepository:        authRepository,
		passwordHasher:        passwordHasher,
		emailSender:           emailSender,
		githubOAuthClient:     githubOAuthClient,
		avatarStorage:         avatarStorage,
		sessionTTL:            cfg.SessionTTL,
		sessionRefreshWindow:  cfg.SessionRefreshWindow,
		passwordResetTokenTTL: cfg.PasswordResetTokenTTL,
		emailVerificationTTL:  cfg.EmailVerificationTTL,
		avatarUploadURLTTL:    cfg.AvatarUploadURLTTL,
		logger:                cfg.Logger,
	}
}

func (s *AuthService) Register(ctx context.Context, input RegisterInput) (RegisterResult, error) {
	email := normalizeEmail(input.Email)
	displayName, err := validateDisplayName(input.DisplayName)
	if err != nil {
		return RegisterResult{}, ErrInvalidRegisterInput
	}

	password := input.Password
	if email == "" || !isPasswordWithinBounds(password) {
		return RegisterResult{}, ErrInvalidRegisterInput
	}

	passwordHash, err := s.passwordHasher.Hash(password)
	if err != nil {
		return RegisterResult{}, fmt.Errorf("hash password: %w", err)
	}

	userID, err := uuid.NewV7()
	if err != nil {
		return RegisterResult{}, fmt.Errorf("generate user id: %w", err)
	}

	sessionID, err := uuid.NewV7()
	if err != nil {
		return RegisterResult{}, fmt.Errorf("generate session id: %w", err)
	}

	sessionToken, sessionTokenHash, err := auth.GenerateSessionToken()
	if err != nil {
		return RegisterResult{}, fmt.Errorf("generate session token: %w", err)
	}

	expiresAt := time.Now().UTC().Add(s.sessionTTL)

	registered, err := s.authRepository.CreateUserAndSession(ctx, repository.RegisterParams{
		UserID:           userID,
		Email:            email,
		PasswordHash:     passwordHash,
		DisplayName:      displayName,
		Role:             defaultUserRole,
		SessionID:        sessionID,
		SessionTokenHash: sessionTokenHash,
		SessionExpiresAt: expiresAt,
		IPAddress:        clampString(input.RemoteIP, 64),
		UserAgent:        clampString(input.UserAgent, 512),
	})
	if err != nil {
		switch {
		case errors.Is(err, repository.ErrEmailAlreadyExists):
			return RegisterResult{}, ErrEmailAlreadyInUse
		case errors.Is(err, repository.ErrDisplayNameAlreadyExists):
			return RegisterResult{}, ErrDisplayNameAlreadyInUse
		default:
			return RegisterResult{}, fmt.Errorf("create user and session: %w", err)
		}
	}

	if err := s.issueAndSendVerificationEmail(ctx, registered.User); err != nil {
		return RegisterResult{}, err
	}

	return RegisterResult{
		User:    toUserView(registered.User),
		Session: SessionView{Token: sessionToken, ExpiresAt: registered.Session.ExpiresAt},
	}, nil
}

func (s *AuthService) Login(ctx context.Context, input LoginInput) (LoginResult, error) {
	email := normalizeEmail(input.Email)
	password := input.Password

	if email == "" || password == "" {
		return LoginResult{}, ErrInvalidLoginInput
	}

	user, err := s.authRepository.GetUserByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, repository.ErrUserNotFound) {
			return LoginResult{}, ErrInvalidCredentials
		}

		return LoginResult{}, fmt.Errorf("get user by email for login: %w", err)
	}

	isValidPassword, err := s.passwordHasher.Verify(password, user.PasswordHash)
	if err != nil {
		return LoginResult{}, fmt.Errorf("verify password: %w", err)
	}

	if !isValidPassword {
		return LoginResult{}, ErrInvalidCredentials
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

func (s *AuthService) Logout(ctx context.Context, sessionToken string) error {
	rawToken := trimSpace(sessionToken)
	if rawToken == "" {
		return nil
	}

	if err := s.authRepository.DeleteSessionByTokenHash(ctx, auth.HashSessionToken(rawToken)); err != nil {
		return fmt.Errorf("delete session by token hash: %w", err)
	}

	return nil
}

func (s *AuthService) AuthenticateSession(ctx context.Context, sessionToken string) (AuthenticatedSession, error) {
	rawToken := trimSpace(sessionToken)
	if rawToken == "" {
		return AuthenticatedSession{}, ErrInvalidSession
	}

	session, err := s.authRepository.GetSessionByTokenHashActive(ctx, auth.HashSessionToken(rawToken))
	if err != nil {
		if errors.Is(err, repository.ErrSessionNotFound) {
			return AuthenticatedSession{}, ErrInvalidSession
		}

		return AuthenticatedSession{}, fmt.Errorf("get active session by token hash: %w", err)
	}

	user, err := s.authRepository.GetUserByID(ctx, session.UserID)
	if err != nil {
		if errors.Is(err, repository.ErrUserNotFound) {
			return AuthenticatedSession{}, ErrInvalidSession
		}

		return AuthenticatedSession{}, fmt.Errorf("get user for session: %w", err)
	}

	expiresAt := session.ExpiresAt
	refreshed := false

	now := time.Now().UTC()
	if shouldRefreshSession(now, expiresAt, s.sessionRefreshWindow) {
		refreshedSession, err := s.authRepository.RefreshSessionExpiry(ctx, session.ID, now.Add(s.sessionTTL))
		if err != nil {
			if errors.Is(err, repository.ErrSessionNotFound) {
				return AuthenticatedSession{}, ErrInvalidSession
			}

			return AuthenticatedSession{}, fmt.Errorf("refresh session expiry: %w", err)
		}

		expiresAt = refreshedSession.ExpiresAt
		refreshed = true
	}

	return AuthenticatedSession{
		User:      toUserView(user),
		ExpiresAt: expiresAt,
		Refreshed: refreshed,
	}, nil
}

func (s *AuthService) ForgotPassword(ctx context.Context, email string) error {
	normalizedEmail := normalizeEmail(email)
	if normalizedEmail == "" {
		return ErrInvalidForgotPasswordInput
	}

	user, err := s.authRepository.GetUserByEmail(ctx, normalizedEmail)
	if err != nil {
		if errors.Is(err, repository.ErrUserNotFound) {
			return nil
		}

		return fmt.Errorf("get user by email: %w", err)
	}

	rawToken, tokenHash, err := auth.GenerateEmailToken()
	if err != nil {
		return fmt.Errorf("generate password reset token: %w", err)
	}

	expiresAt := time.Now().UTC().Add(s.passwordResetTokenTTL)

	if _, err := s.authRepository.IssueEmailToken(ctx, repository.IssueEmailTokenParams{
		UserID:    user.ID,
		Type:      repository.EmailTokenTypePasswordReset,
		TokenHash: tokenHash,
		ExpiresAt: expiresAt,
	}); err != nil {
		return fmt.Errorf("issue password reset token: %w", err)
	}

	if err := s.emailSender.SendPasswordResetEmail(ctx, user.Email, user.DisplayName, rawToken); err != nil {
		s.logEmailDeliveryFailure("password_reset_email_send_failed", user.Email, err)
		return nil
	}

	return nil
}

func (s *AuthService) ResetPassword(ctx context.Context, token, password string) error {
	rawToken := trimSpace(token)
	if rawToken == "" || !isPasswordWithinBounds(password) {
		return ErrInvalidResetPasswordInput
	}

	passwordHash, err := s.passwordHasher.Hash(password)
	if err != nil {
		return fmt.Errorf("hash new password: %w", err)
	}

	if err := s.authRepository.ResetPasswordByToken(ctx, repository.ResetPasswordByTokenParams{
		TokenHash:       auth.HashEmailToken(rawToken),
		NewPasswordHash: passwordHash,
	}); err != nil {
		if errors.Is(err, repository.ErrInvalidEmailToken) {
			return ErrInvalidOrExpiredResetToken
		}

		return fmt.Errorf("reset password by token: %w", err)
	}

	return nil
}

func (s *AuthService) VerifyEmail(ctx context.Context, token string) error {
	rawToken := trimSpace(token)
	if rawToken == "" {
		return ErrInvalidVerifyEmailInput
	}

	if _, err := s.authRepository.VerifyEmailByToken(ctx, auth.HashEmailToken(rawToken)); err != nil {
		if errors.Is(err, repository.ErrInvalidEmailToken) {
			return ErrInvalidOrExpiredVerificationToken
		}

		return fmt.Errorf("verify email by token: %w", err)
	}

	return nil
}

func (s *AuthService) ResendVerificationEmail(ctx context.Context, userID uuid.UUID) error {
	if userID == uuid.Nil {
		return ErrInvalidSession
	}

	user, err := s.authRepository.GetUserByID(ctx, userID)
	if err != nil {
		if errors.Is(err, repository.ErrUserNotFound) {
			return ErrInvalidSession
		}

		return fmt.Errorf("get user by id for resend verification: %w", err)
	}

	if user.EmailVerifiedAt != nil {
		return nil
	}

	if err := s.issueAndSendVerificationEmail(ctx, user); err != nil {
		return fmt.Errorf("issue and send verification email: %w", err)
	}

	return nil
}

func (s *AuthService) rotateSessionForUser(ctx context.Context, userID uuid.UUID, currentSessionToken, remoteIP, userAgent string) (repository.Session, string, error) {
	sessionID, err := uuid.NewV7()
	if err != nil {
		return repository.Session{}, "", fmt.Errorf("generate session id: %w", err)
	}

	sessionToken, sessionTokenHash, err := auth.GenerateSessionToken()
	if err != nil {
		return repository.Session{}, "", fmt.Errorf("generate session token: %w", err)
	}

	var previousSessionHash []byte
	if existingToken := trimSpace(currentSessionToken); existingToken != "" {
		previousSessionHash = auth.HashSessionToken(existingToken)
	}

	rotatedSession, err := s.authRepository.RotateSession(ctx, repository.RotateSessionParams{
		SessionID:         sessionID,
		UserID:            userID,
		TokenHash:         sessionTokenHash,
		ExpiresAt:         time.Now().UTC().Add(s.sessionTTL),
		IPAddress:         clampString(remoteIP, 64),
		UserAgent:         clampString(userAgent, 512),
		PreviousTokenHash: previousSessionHash,
	})
	if err != nil {
		return repository.Session{}, "", fmt.Errorf("rotate login session: %w", err)
	}

	return rotatedSession, sessionToken, nil
}

func (s *AuthService) issueAndSendVerificationEmail(ctx context.Context, user repository.User) error {
	rawToken, tokenHash, err := auth.GenerateEmailToken()
	if err != nil {
		return fmt.Errorf("generate email verification token: %w", err)
	}

	expiresAt := time.Now().UTC().Add(s.emailVerificationTTL)

	if _, err := s.authRepository.IssueEmailToken(ctx, repository.IssueEmailTokenParams{
		UserID:    user.ID,
		Type:      repository.EmailTokenTypeEmailVerification,
		TokenHash: tokenHash,
		ExpiresAt: expiresAt,
	}); err != nil {
		return fmt.Errorf("issue email verification token: %w", err)
	}

	if err := s.emailSender.SendVerificationEmail(ctx, user.Email, user.DisplayName, rawToken); err != nil {
		s.logEmailDeliveryFailure("verification_email_send_failed", user.Email, err)
		return nil
	}

	return nil
}

func (s *AuthService) logEmailDeliveryFailure(eventName, email string, err error) {
	logger := s.logger
	if logger == nil {
		return
	}

	logger.Error(
		eventName,
		slog.String("email", email),
		slog.Any("err", err),
	)
}

func toUserView(user repository.User) UserView {
	return UserView{
		ID:              user.ID,
		Email:           user.Email,
		DisplayName:     user.DisplayName,
		Role:            user.Role,
		EmailVerifiedAt: user.EmailVerifiedAt,
		AvatarMetadata:  cloneJSON(user.AvatarMetadata),
		InsertedAt:      user.InsertedAt,
		UpdatedAt:       user.UpdatedAt,
	}
}

func trimSpace(value string) string {
	return strings.TrimSpace(value)
}
