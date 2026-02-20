package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"strings"
	"time"
	"unicode"

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
)

const (
	defaultUserRole             = "user"
	defaultSessionRefreshIn     = 24 * time.Hour
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

var validDisplayNameRegexp = regexp.MustCompile(`^[\p{L}\p{N}_\- ]+$`)

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
}

type authRepository interface {
	CreateUserAndSession(ctx context.Context, params repository.RegisterParams) (repository.RegisterResult, error)
	CreateUser(ctx context.Context, params repository.CreateUserParams) (repository.User, error)
	GetUserByEmail(ctx context.Context, email string) (repository.User, error)
	GetUserByID(ctx context.Context, userID uuid.UUID) (repository.User, error)
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
	CreatePresignedUploadURL(ctx context.Context, objectKey, contentType string) (client.PresignedUpload, error)
	HeadObject(ctx context.Context, objectKey string) (client.ObjectMetadata, error)
	ReadObjectPrefix(ctx context.Context, objectKey string, maxBytes int64) ([]byte, error)
	DeleteObject(ctx context.Context, objectKey string) error
	PublicURL(objectKey string) string
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
	UserID         uuid.UUID
	DisplayName    *string
	AvatarMetadata *json.RawMessage
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

func NewAuthService(
	authRepository authRepository,
	passwordHasher passwordHasher,
	emailSender authEmailSender,
	githubOAuthClient githubOAuthClient,
	avatarStorage avatarStorage,
	sessionTTL time.Duration,
	sessionRefreshWindow time.Duration,
	passwordResetTokenTTL time.Duration,
	emailVerificationTTL time.Duration,
	avatarUploadURLTTL time.Duration,
) *AuthService {
	if sessionTTL <= 0 {
		sessionTTL = 30 * 24 * time.Hour
	}

	if sessionRefreshWindow <= 0 {
		sessionRefreshWindow = defaultSessionRefreshIn
	}

	if sessionRefreshWindow > sessionTTL {
		sessionRefreshWindow = sessionTTL
	}

	if passwordResetTokenTTL <= 0 {
		passwordResetTokenTTL = defaultPasswordResetTTL
	}

	if emailVerificationTTL <= 0 {
		emailVerificationTTL = defaultEmailVerificationTTL
	}

	if avatarUploadURLTTL <= 0 {
		avatarUploadURLTTL = defaultAvatarUploadURLTTL
	}

	if emailSender == nil {
		emailSender = client.NewNoopAuthEmailSender(nil)
	}

	if isNilInterface(githubOAuthClient) {
		githubOAuthClient = nil
	}

	if isNilInterface(avatarStorage) {
		avatarStorage = nil
	}

	return &AuthService{
		authRepository:        authRepository,
		passwordHasher:        passwordHasher,
		emailSender:           emailSender,
		githubOAuthClient:     githubOAuthClient,
		avatarStorage:         avatarStorage,
		sessionTTL:            sessionTTL,
		sessionRefreshWindow:  sessionRefreshWindow,
		passwordResetTokenTTL: passwordResetTokenTTL,
		emailVerificationTTL:  emailVerificationTTL,
		avatarUploadURLTTL:    avatarUploadURLTTL,
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
		IPAddress:        clampString(strings.TrimSpace(input.RemoteIP), 64),
		UserAgent:        clampString(strings.TrimSpace(input.UserAgent), 512),
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
		return RegisterResult{}, fmt.Errorf("send verification email: %w", err)
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
	rawToken := strings.TrimSpace(sessionToken)
	if rawToken == "" {
		return nil
	}

	if err := s.authRepository.DeleteSessionByTokenHash(ctx, auth.HashSessionToken(rawToken)); err != nil {
		return fmt.Errorf("delete session by token hash: %w", err)
	}

	return nil
}

func (s *AuthService) AuthenticateSession(ctx context.Context, sessionToken string) (AuthenticatedSession, error) {
	rawToken := strings.TrimSpace(sessionToken)
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
		return fmt.Errorf("send password reset email: %w", err)
	}

	return nil
}

func (s *AuthService) ResetPassword(ctx context.Context, token, password string) error {
	rawToken := strings.TrimSpace(token)
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
	rawToken := strings.TrimSpace(token)
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

func (s *AuthService) UpdateProfile(ctx context.Context, input UpdateProfileInput) (UserView, error) {
	if input.UserID == uuid.Nil {
		return UserView{}, ErrInvalidSession
	}

	if input.DisplayName == nil && input.AvatarMetadata == nil {
		return UserView{}, ErrInvalidProfileUpdateInput
	}

	user, err := s.authRepository.GetUserByID(ctx, input.UserID)
	if err != nil {
		if errors.Is(err, repository.ErrUserNotFound) {
			return UserView{}, ErrInvalidSession
		}

		return UserView{}, fmt.Errorf("get user for profile update: %w", err)
	}

	updatedDisplayName := user.DisplayName
	if input.DisplayName != nil {
		displayName, err := validateDisplayName(*input.DisplayName)
		if err != nil {
			return UserView{}, ErrInvalidProfileUpdateInput
		}
		updatedDisplayName = displayName
	}

	updatedAvatarMetadata := user.AvatarMetadata
	if input.AvatarMetadata != nil {
		avatarMetadata, err := normalizeAvatarMetadata(*input.AvatarMetadata)
		if err != nil {
			return UserView{}, ErrInvalidProfileUpdateInput
		}
		updatedAvatarMetadata = avatarMetadata
	}

	updatedUser, err := s.authRepository.UpdateUserProfile(ctx, repository.UpdateUserProfileParams{
		UserID:         user.ID,
		DisplayName:    updatedDisplayName,
		AvatarMetadata: updatedAvatarMetadata,
	})
	if err != nil {
		switch {
		case errors.Is(err, repository.ErrDisplayNameAlreadyExists):
			return UserView{}, ErrDisplayNameAlreadyInUse
		case errors.Is(err, repository.ErrUserNotFound):
			return UserView{}, ErrInvalidSession
		default:
			return UserView{}, fmt.Errorf("update user profile: %w", err)
		}
	}

	return toUserView(updatedUser), nil
}

func (s *AuthService) CreateAvatarUploadURL(ctx context.Context, input CreateAvatarUploadURLInput) (CreateAvatarUploadURLResult, error) {
	if input.UserID == uuid.Nil {
		return CreateAvatarUploadURLResult{}, ErrInvalidSession
	}

	if s.avatarStorage == nil {
		return CreateAvatarUploadURLResult{}, ErrAvatarStorageUnavailable
	}

	normalizedContentType, fileExtension, err := normalizeAvatarContentType(input.ContentType)
	if err != nil {
		return CreateAvatarUploadURLResult{}, err
	}

	if input.ContentLength <= 0 {
		return CreateAvatarUploadURLResult{}, ErrInvalidAvatarUploadInput
	}

	if input.ContentLength > maxAvatarUploadBytes {
		return CreateAvatarUploadURLResult{}, ErrAvatarFileTooLarge
	}

	objectKey, err := newAvatarObjectKey(input.UserID, fileExtension)
	if err != nil {
		return CreateAvatarUploadURLResult{}, fmt.Errorf("generate avatar object key: %w", err)
	}

	presignedUpload, err := s.avatarStorage.CreatePresignedUploadURL(ctx, objectKey, normalizedContentType)
	if err != nil {
		return CreateAvatarUploadURLResult{}, fmt.Errorf("create avatar upload url: %w", err)
	}

	headers := make(map[string]string, len(presignedUpload.Headers))
	for key, value := range presignedUpload.Headers {
		headers[key] = value
	}

	expiresAt := presignedUpload.ExpiresAt
	if expiresAt.IsZero() {
		expiresAt = time.Now().UTC().Add(s.avatarUploadURLTTL)
	}

	return CreateAvatarUploadURLResult{
		UploadURL: presignedUpload.URL,
		Method:    presignedUpload.Method,
		ObjectKey: presignedUpload.ObjectKey,
		ExpiresAt: expiresAt,
		Headers:   headers,
	}, nil
}

func (s *AuthService) ConfirmAvatarUpload(ctx context.Context, input ConfirmAvatarUploadInput) (UserView, error) {
	if input.UserID == uuid.Nil {
		return UserView{}, ErrInvalidSession
	}

	if s.avatarStorage == nil {
		return UserView{}, ErrAvatarStorageUnavailable
	}

	objectKey, err := normalizeAvatarObjectKey(input.ObjectKey)
	if err != nil {
		return UserView{}, ErrInvalidAvatarUploadInput
	}

	if !isOwnedAvatarObjectKey(input.UserID, objectKey) {
		return UserView{}, ErrInvalidAvatarUploadInput
	}

	avatarObject, err := s.avatarStorage.HeadObject(ctx, objectKey)
	if err != nil {
		if errors.Is(err, client.ErrObjectNotFound) {
			return UserView{}, ErrAvatarObjectNotFound
		}

		return UserView{}, fmt.Errorf("head avatar object: %w", err)
	}

	normalizedContentType, _, err := normalizeAvatarContentType(avatarObject.ContentType)
	if err != nil {
		return UserView{}, ErrUnsupportedAvatarContentType
	}

	if avatarObject.ContentLength <= 0 {
		return UserView{}, ErrInvalidAvatarUploadInput
	}

	if avatarObject.ContentLength > maxAvatarUploadBytes {
		return UserView{}, ErrAvatarFileTooLarge
	}

	avatarPrefix, err := s.avatarStorage.ReadObjectPrefix(ctx, objectKey, avatarMagicBytesReadLimit)
	if err != nil {
		if errors.Is(err, client.ErrObjectNotFound) {
			return UserView{}, ErrAvatarObjectNotFound
		}

		return UserView{}, fmt.Errorf("read avatar object prefix: %w", err)
	}

	if err := validateAvatarMagicBytes(normalizedContentType, avatarPrefix); err != nil {
		if errors.Is(err, ErrInvalidAvatarFileContent) {
			return UserView{}, ErrInvalidAvatarFileContent
		}

		return UserView{}, fmt.Errorf("validate avatar object content: %w", err)
	}

	user, err := s.authRepository.GetUserByID(ctx, input.UserID)
	if err != nil {
		if errors.Is(err, repository.ErrUserNotFound) {
			return UserView{}, ErrInvalidSession
		}

		return UserView{}, fmt.Errorf("get user for avatar confirm: %w", err)
	}

	avatarMetadata := map[string]any{
		"provider":     "r2",
		"key":          objectKey,
		"url":          s.avatarStorage.PublicURL(objectKey),
		"content_type": normalizedContentType,
		"size_bytes":   avatarObject.ContentLength,
		"updated_at":   time.Now().UTC().Format(time.RFC3339Nano),
	}

	if avatarObject.ETag != "" {
		avatarMetadata["etag"] = avatarObject.ETag
	}

	if !avatarObject.LastModified.IsZero() {
		avatarMetadata["last_modified"] = avatarObject.LastModified.UTC().Format(time.RFC3339Nano)
	}

	normalizedAvatarMetadata, err := json.Marshal(avatarMetadata)
	if err != nil {
		return UserView{}, fmt.Errorf("marshal avatar metadata: %w", err)
	}

	updatedUser, err := s.authRepository.UpdateUserProfile(ctx, repository.UpdateUserProfileParams{
		UserID:         user.ID,
		DisplayName:    user.DisplayName,
		AvatarMetadata: json.RawMessage(normalizedAvatarMetadata),
	})
	if err != nil {
		switch {
		case errors.Is(err, repository.ErrDisplayNameAlreadyExists):
			return UserView{}, ErrDisplayNameAlreadyInUse
		case errors.Is(err, repository.ErrUserNotFound):
			return UserView{}, ErrInvalidSession
		default:
			return UserView{}, fmt.Errorf("update avatar metadata: %w", err)
		}
	}

	return toUserView(updatedUser), nil
}

func (s *AuthService) DeleteAvatar(ctx context.Context, userID uuid.UUID) (UserView, error) {
	if userID == uuid.Nil {
		return UserView{}, ErrInvalidSession
	}

	user, err := s.authRepository.GetUserByID(ctx, userID)
	if err != nil {
		if errors.Is(err, repository.ErrUserNotFound) {
			return UserView{}, ErrInvalidSession
		}

		return UserView{}, fmt.Errorf("get user for avatar delete: %w", err)
	}

	if s.avatarStorage != nil {
		objectKey := avatarObjectKeyFromMetadata(user.AvatarMetadata)
		if objectKey != "" {
			if err := s.avatarStorage.DeleteObject(ctx, objectKey); err != nil {
				if !errors.Is(err, client.ErrObjectNotFound) {
					return UserView{}, fmt.Errorf("delete avatar object: %w", err)
				}
			}
		}
	}

	updatedUser, err := s.authRepository.UpdateUserProfile(ctx, repository.UpdateUserProfileParams{
		UserID:         user.ID,
		DisplayName:    user.DisplayName,
		AvatarMetadata: json.RawMessage("{}"),
	})
	if err != nil {
		switch {
		case errors.Is(err, repository.ErrDisplayNameAlreadyExists):
			return UserView{}, ErrDisplayNameAlreadyInUse
		case errors.Is(err, repository.ErrUserNotFound):
			return UserView{}, ErrInvalidSession
		default:
			return UserView{}, fmt.Errorf("clear avatar metadata: %w", err)
		}
	}

	return toUserView(updatedUser), nil
}

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
	if existingToken := strings.TrimSpace(currentSessionToken); existingToken != "" {
		previousSessionHash = auth.HashSessionToken(existingToken)
	}

	rotatedSession, err := s.authRepository.RotateSession(ctx, repository.RotateSessionParams{
		SessionID:         sessionID,
		UserID:            userID,
		TokenHash:         sessionTokenHash,
		ExpiresAt:         time.Now().UTC().Add(s.sessionTTL),
		IPAddress:         clampString(strings.TrimSpace(remoteIP), 64),
		UserAgent:         clampString(strings.TrimSpace(userAgent), 512),
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
		return fmt.Errorf("send verification email: %w", err)
	}

	return nil
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

func normalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

func clampString(value string, maxLen int) string {
	if len(value) <= maxLen {
		return value
	}

	return value[:maxLen]
}

func isPasswordWithinBounds(password string) bool {
	length := len(password)
	return length >= minPasswordLen && length <= maxPasswordLen
}

func shouldRefreshSession(now, expiresAt time.Time, refreshWindow time.Duration) bool {
	if refreshWindow <= 0 {
		return false
	}

	return now.Add(refreshWindow).After(expiresAt)
}

func validateDisplayName(displayName string) (string, error) {
	trimmed := strings.TrimSpace(displayName)
	if len(trimmed) < minDisplayNameLength || len(trimmed) > maxDisplayNameLength {
		return "", errors.New("display name length is invalid")
	}

	if !validDisplayNameRegexp.MatchString(trimmed) {
		return "", errors.New("display name contains invalid characters")
	}

	return trimmed, nil
}

func normalizeAvatarMetadata(raw json.RawMessage) (json.RawMessage, error) {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" {
		return json.RawMessage("{}"), nil
	}

	if len(trimmed) > maxAvatarMetadataBytes {
		return nil, errors.New("avatar metadata is too large")
	}

	var decoded map[string]any
	if err := json.Unmarshal([]byte(trimmed), &decoded); err != nil {
		return nil, errors.New("avatar metadata must be a valid JSON object")
	}

	normalized, err := json.Marshal(decoded)
	if err != nil {
		return nil, fmt.Errorf("normalize avatar metadata: %w", err)
	}

	return json.RawMessage(normalized), nil
}

func normalizeAvatarContentType(contentType string) (string, string, error) {
	trimmed := strings.ToLower(strings.TrimSpace(contentType))
	if trimmed == "" {
		return "", "", ErrInvalidAvatarUploadInput
	}

	if mediaType, _, found := strings.Cut(trimmed, ";"); found {
		trimmed = strings.TrimSpace(mediaType)
	}

	switch trimmed {
	case "image/jpeg", "image/jpg":
		return "image/jpeg", ".jpg", nil
	case "image/png":
		return "image/png", ".png", nil
	case "image/webp":
		return "image/webp", ".webp", nil
	default:
		return "", "", ErrUnsupportedAvatarContentType
	}
}

func validateAvatarMagicBytes(contentType string, prefix []byte) error {
	if len(prefix) == 0 {
		return ErrInvalidAvatarFileContent
	}

	switch contentType {
	case "image/jpeg":
		if hasJPEGSignature(prefix) {
			return nil
		}
	case "image/png":
		if hasPNGSignature(prefix) {
			return nil
		}
	case "image/webp":
		if hasWebPSignature(prefix) {
			return nil
		}
	default:
		return ErrUnsupportedAvatarContentType
	}

	return ErrInvalidAvatarFileContent
}

func hasJPEGSignature(data []byte) bool {
	return len(data) >= 3 &&
		data[0] == 0xFF &&
		data[1] == 0xD8 &&
		data[2] == 0xFF
}

func hasPNGSignature(data []byte) bool {
	if len(data) < 8 {
		return false
	}

	pngSignature := []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}
	for index, b := range pngSignature {
		if data[index] != b {
			return false
		}
	}

	return true
}

func hasWebPSignature(data []byte) bool {
	if len(data) < 12 {
		return false
	}

	return string(data[0:4]) == "RIFF" && string(data[8:12]) == "WEBP"
}

func newAvatarObjectKey(userID uuid.UUID, extension string) (string, error) {
	avatarID, err := uuid.NewV7()
	if err != nil {
		return "", err
	}

	trimmedExtension := strings.TrimSpace(extension)
	if trimmedExtension == "" {
		trimmedExtension = ".bin"
	}

	return fmt.Sprintf("users/%s/avatars/%s%s", userID.String(), avatarID.String(), trimmedExtension), nil
}

func normalizeAvatarObjectKey(objectKey string) (string, error) {
	trimmed := strings.Trim(strings.TrimSpace(objectKey), "/")
	if trimmed == "" {
		return "", errors.New("object key is required")
	}

	if strings.Contains(trimmed, "..") {
		return "", errors.New("object key contains invalid path segments")
	}

	return trimmed, nil
}

func isOwnedAvatarObjectKey(userID uuid.UUID, objectKey string) bool {
	prefix := fmt.Sprintf("users/%s/avatars/", userID.String())
	return strings.HasPrefix(objectKey, prefix)
}

func avatarObjectKeyFromMetadata(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}

	var metadata map[string]any
	if err := json.Unmarshal(raw, &metadata); err != nil {
		return ""
	}

	value, ok := metadata["key"]
	if !ok {
		return ""
	}

	key, ok := value.(string)
	if !ok {
		return ""
	}

	normalizedKey, err := normalizeAvatarObjectKey(key)
	if err != nil {
		return ""
	}

	return normalizedKey
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

func cloneJSON(raw json.RawMessage) json.RawMessage {
	if len(raw) == 0 {
		return json.RawMessage("{}")
	}

	cloned := make([]byte, len(raw))
	copy(cloned, raw)
	return json.RawMessage(cloned)
}

func isNilInterface(value any) bool {
	if value == nil {
		return true
	}

	rv := reflect.ValueOf(value)
	switch rv.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return rv.IsNil()
	default:
		return false
	}
}
