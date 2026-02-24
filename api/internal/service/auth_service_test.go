package service

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/katsutoo/kickoutchi/api/internal/client"
	"github.com/katsutoo/kickoutchi/api/internal/repository"
)

type fakeAuthRepository struct {
	createUserAndSessionFn          func(ctx context.Context, params repository.RegisterParams) (repository.RegisterResult, error)
	createUserFn                    func(ctx context.Context, params repository.CreateUserParams) (repository.User, error)
	getUserByEmailFn                func(ctx context.Context, email string) (repository.User, error)
	getUserByIDFn                   func(ctx context.Context, userID uuid.UUID) (repository.User, error)
	updateUserProfileFn             func(ctx context.Context, params repository.UpdateUserProfileParams) (repository.User, error)
	rotateSessionFn                 func(ctx context.Context, params repository.RotateSessionParams) (repository.Session, error)
	getSessionByTokenHashActiveFn   func(ctx context.Context, tokenHash []byte) (repository.Session, error)
	refreshSessionExpiryFn          func(ctx context.Context, sessionID uuid.UUID, expiresAt time.Time) (repository.Session, error)
	deleteSessionByTokenHashFn      func(ctx context.Context, tokenHash []byte) error
	issueEmailTokenFn               func(ctx context.Context, params repository.IssueEmailTokenParams) (repository.EmailToken, error)
	verifyEmailByTokenFn            func(ctx context.Context, tokenHash []byte) (repository.User, error)
	resetPasswordByTokenFn          func(ctx context.Context, params repository.ResetPasswordByTokenParams) error
	getOAuthIdentityByProviderUIDFn func(ctx context.Context, provider, providerUID string) (repository.OAuthIdentity, error)
	createOAuthIdentityFn           func(ctx context.Context, params repository.CreateOAuthIdentityParams) (repository.OAuthIdentity, error)
}

func (f *fakeAuthRepository) CreateUserAndSession(ctx context.Context, params repository.RegisterParams) (repository.RegisterResult, error) {
	if f.createUserAndSessionFn != nil {
		return f.createUserAndSessionFn(ctx, params)
	}

	return repository.RegisterResult{}, errors.New("unexpected CreateUserAndSession call")
}

func (f *fakeAuthRepository) CreateUser(ctx context.Context, params repository.CreateUserParams) (repository.User, error) {
	if f.createUserFn != nil {
		return f.createUserFn(ctx, params)
	}

	return repository.User{}, errors.New("unexpected CreateUser call")
}

func (f *fakeAuthRepository) GetUserByEmail(ctx context.Context, email string) (repository.User, error) {
	if f.getUserByEmailFn != nil {
		return f.getUserByEmailFn(ctx, email)
	}

	return repository.User{}, errors.New("unexpected GetUserByEmail call")
}

func (f *fakeAuthRepository) GetUserByID(ctx context.Context, userID uuid.UUID) (repository.User, error) {
	if f.getUserByIDFn != nil {
		return f.getUserByIDFn(ctx, userID)
	}

	return repository.User{}, errors.New("unexpected GetUserByID call")
}

func (f *fakeAuthRepository) UpdateUserProfile(ctx context.Context, params repository.UpdateUserProfileParams) (repository.User, error) {
	if f.updateUserProfileFn != nil {
		return f.updateUserProfileFn(ctx, params)
	}

	return repository.User{}, errors.New("unexpected UpdateUserProfile call")
}

func (f *fakeAuthRepository) RotateSession(ctx context.Context, params repository.RotateSessionParams) (repository.Session, error) {
	if f.rotateSessionFn != nil {
		return f.rotateSessionFn(ctx, params)
	}

	return repository.Session{}, errors.New("unexpected RotateSession call")
}

func (f *fakeAuthRepository) GetSessionByTokenHashActive(ctx context.Context, tokenHash []byte) (repository.Session, error) {
	if f.getSessionByTokenHashActiveFn != nil {
		return f.getSessionByTokenHashActiveFn(ctx, tokenHash)
	}

	return repository.Session{}, errors.New("unexpected GetSessionByTokenHashActive call")
}

func (f *fakeAuthRepository) RefreshSessionExpiry(ctx context.Context, sessionID uuid.UUID, expiresAt time.Time) (repository.Session, error) {
	if f.refreshSessionExpiryFn != nil {
		return f.refreshSessionExpiryFn(ctx, sessionID, expiresAt)
	}

	return repository.Session{}, errors.New("unexpected RefreshSessionExpiry call")
}

func (f *fakeAuthRepository) DeleteSessionByTokenHash(ctx context.Context, tokenHash []byte) error {
	if f.deleteSessionByTokenHashFn != nil {
		return f.deleteSessionByTokenHashFn(ctx, tokenHash)
	}

	return nil
}

func (f *fakeAuthRepository) IssueEmailToken(ctx context.Context, params repository.IssueEmailTokenParams) (repository.EmailToken, error) {
	if f.issueEmailTokenFn != nil {
		return f.issueEmailTokenFn(ctx, params)
	}

	return repository.EmailToken{}, errors.New("unexpected IssueEmailToken call")
}

func (f *fakeAuthRepository) VerifyEmailByToken(ctx context.Context, tokenHash []byte) (repository.User, error) {
	if f.verifyEmailByTokenFn != nil {
		return f.verifyEmailByTokenFn(ctx, tokenHash)
	}

	return repository.User{}, errors.New("unexpected VerifyEmailByToken call")
}

func (f *fakeAuthRepository) ResetPasswordByToken(ctx context.Context, params repository.ResetPasswordByTokenParams) error {
	if f.resetPasswordByTokenFn != nil {
		return f.resetPasswordByTokenFn(ctx, params)
	}

	return errors.New("unexpected ResetPasswordByToken call")
}

func (f *fakeAuthRepository) GetOAuthIdentityByProviderUID(ctx context.Context, provider, providerUID string) (repository.OAuthIdentity, error) {
	if f.getOAuthIdentityByProviderUIDFn != nil {
		return f.getOAuthIdentityByProviderUIDFn(ctx, provider, providerUID)
	}

	return repository.OAuthIdentity{}, errors.New("unexpected GetOAuthIdentityByProviderUID call")
}

func (f *fakeAuthRepository) CreateOAuthIdentity(ctx context.Context, params repository.CreateOAuthIdentityParams) (repository.OAuthIdentity, error) {
	if f.createOAuthIdentityFn != nil {
		return f.createOAuthIdentityFn(ctx, params)
	}

	return repository.OAuthIdentity{}, errors.New("unexpected CreateOAuthIdentity call")
}

type fakePasswordHasher struct {
	hashFn   func(password string) (string, error)
	verifyFn func(password, encodedHash string) (bool, error)
}

func (f *fakePasswordHasher) Hash(password string) (string, error) {
	if f.hashFn != nil {
		return f.hashFn(password)
	}

	return "", errors.New("unexpected Hash call")
}

func (f *fakePasswordHasher) Verify(password, encodedHash string) (bool, error) {
	if f.verifyFn != nil {
		return f.verifyFn(password, encodedHash)
	}

	return false, errors.New("unexpected Verify call")
}

type fakeAuthEmailSender struct {
	sendVerificationFn  func(ctx context.Context, toEmail, displayName, token string) error
	sendPasswordResetFn func(ctx context.Context, toEmail, displayName, token string) error
}

func (f *fakeAuthEmailSender) SendVerificationEmail(ctx context.Context, toEmail, displayName, token string) error {
	if f.sendVerificationFn != nil {
		return f.sendVerificationFn(ctx, toEmail, displayName, token)
	}

	return nil
}

func (f *fakeAuthEmailSender) SendPasswordResetEmail(ctx context.Context, toEmail, displayName, token string) error {
	if f.sendPasswordResetFn != nil {
		return f.sendPasswordResetFn(ctx, toEmail, displayName, token)
	}

	return nil
}

type fakeAvatarStorage struct {
	createPresignedUploadURLFn func(ctx context.Context, objectKey, contentType string) (client.PresignedUpload, error)
	headObjectFn               func(ctx context.Context, objectKey string) (client.ObjectMetadata, error)
	readObjectPrefixFn         func(ctx context.Context, objectKey string, maxBytes int64) ([]byte, error)
	deleteObjectFn             func(ctx context.Context, objectKey string) error
	publicURLFn                func(objectKey string) string
}

func (f *fakeAvatarStorage) CreatePresignedUploadURL(ctx context.Context, objectKey, contentType string) (client.PresignedUpload, error) {
	if f.createPresignedUploadURLFn != nil {
		return f.createPresignedUploadURLFn(ctx, objectKey, contentType)
	}

	return client.PresignedUpload{}, errors.New("unexpected CreatePresignedUploadURL call")
}

func (f *fakeAvatarStorage) HeadObject(ctx context.Context, objectKey string) (client.ObjectMetadata, error) {
	if f.headObjectFn != nil {
		return f.headObjectFn(ctx, objectKey)
	}

	return client.ObjectMetadata{}, errors.New("unexpected HeadObject call")
}

func (f *fakeAvatarStorage) ReadObjectPrefix(ctx context.Context, objectKey string, maxBytes int64) ([]byte, error) {
	if f.readObjectPrefixFn != nil {
		return f.readObjectPrefixFn(ctx, objectKey, maxBytes)
	}

	return nil, errors.New("unexpected ReadObjectPrefix call")
}

func (f *fakeAvatarStorage) DeleteObject(ctx context.Context, objectKey string) error {
	if f.deleteObjectFn != nil {
		return f.deleteObjectFn(ctx, objectKey)
	}

	return nil
}

func (f *fakeAvatarStorage) PublicURL(objectKey string) string {
	if f.publicURLFn != nil {
		return f.publicURLFn(objectKey)
	}

	return ""
}

func TestAuthServiceRegister(t *testing.T) {
	t.Run("invalid input", func(t *testing.T) {
		svc := NewAuthService(
			&fakeAuthRepository{},
			&fakePasswordHasher{},
			&fakeAuthEmailSender{},
			nil,
			nil,
			defaultAuthServiceConfig(),
		)

		_, err := svc.Register(t.Context(), RegisterInput{Email: "", Password: "short", DisplayName: "x"})
		if !errors.Is(err, ErrInvalidRegisterInput) {
			t.Fatalf("expected ErrInvalidRegisterInput, got: %v", err)
		}
	})

	t.Run("email conflict", func(t *testing.T) {
		svc := NewAuthService(
			&fakeAuthRepository{
				createUserAndSessionFn: func(context.Context, repository.RegisterParams) (repository.RegisterResult, error) {
					return repository.RegisterResult{}, repository.ErrEmailAlreadyExists
				},
			},
			&fakePasswordHasher{hashFn: func(string) (string, error) { return "password_hash", nil }},
			&fakeAuthEmailSender{},
			nil,
			nil,
			defaultAuthServiceConfig(),
		)

		_, err := svc.Register(t.Context(), RegisterInput{Email: "user@example.com", Password: "Str0ngPassw0rd!", DisplayName: "user_name"})
		if !errors.Is(err, ErrEmailAlreadyInUse) {
			t.Fatalf("expected ErrEmailAlreadyInUse, got: %v", err)
		}
	})

	t.Run("success", func(t *testing.T) {
		userID := mustUUIDForServiceTest(t)
		sessionID := mustUUIDForServiceTest(t)

		capturedEmail := ""
		capturedIssueTokenType := ""
		capturedCreateEmail := ""

		svc := NewAuthService(
			&fakeAuthRepository{
				createUserAndSessionFn: func(_ context.Context, params repository.RegisterParams) (repository.RegisterResult, error) {
					capturedCreateEmail = params.Email
					return repository.RegisterResult{
						User: repository.User{
							ID:              userID,
							Email:           params.Email,
							DisplayName:     params.DisplayName,
							Role:            "user",
							AvatarMetadata:  json.RawMessage("{}"),
							InsertedAt:      time.Now().UTC(),
							UpdatedAt:       time.Now().UTC(),
							EmailVerifiedAt: nil,
						},
						Session: repository.Session{
							ID:        sessionID,
							UserID:    userID,
							ExpiresAt: time.Now().UTC().Add(time.Hour),
						},
					}, nil
				},
				issueEmailTokenFn: func(_ context.Context, params repository.IssueEmailTokenParams) (repository.EmailToken, error) {
					capturedIssueTokenType = params.Type
					return repository.EmailToken{}, nil
				},
			},
			&fakePasswordHasher{hashFn: func(string) (string, error) { return "password_hash", nil }},
			&fakeAuthEmailSender{sendVerificationFn: func(_ context.Context, toEmail, _ string, _ string) error {
				capturedEmail = toEmail
				return nil
			}},
			nil,
			nil,
			defaultAuthServiceConfig(),
		)

		result, err := svc.Register(t.Context(), RegisterInput{Email: "USER@Example.com", Password: "Str0ngPassw0rd!", DisplayName: "user_name"})
		if err != nil {
			t.Fatalf("register returned error: %v", err)
		}

		if result.User.Email != "user@example.com" {
			t.Fatalf("expected normalized email, got: %s", result.User.Email)
		}

		if capturedCreateEmail != "user@example.com" {
			t.Fatalf("expected create user email to be normalized, got: %s", capturedCreateEmail)
		}

		if capturedIssueTokenType != repository.EmailTokenTypeEmailVerification {
			t.Fatalf("expected verification token issue type, got: %s", capturedIssueTokenType)
		}

		if capturedEmail != "user@example.com" {
			t.Fatalf("expected verification email sent to normalized address, got: %s", capturedEmail)
		}
	})
}

func TestAuthServiceLogin(t *testing.T) {
	t.Run("invalid credentials when user not found", func(t *testing.T) {
		svc := NewAuthService(
			&fakeAuthRepository{getUserByEmailFn: func(context.Context, string) (repository.User, error) {
				return repository.User{}, repository.ErrUserNotFound
			}},
			&fakePasswordHasher{},
			&fakeAuthEmailSender{},
			nil,
			nil,
			defaultAuthServiceConfig(),
		)

		_, err := svc.Login(t.Context(), LoginInput{Email: "missing@example.com", Password: "Str0ngPassw0rd!"})
		if !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("expected ErrInvalidCredentials, got: %v", err)
		}
	})

	t.Run("success", func(t *testing.T) {
		userID := mustUUIDForServiceTest(t)
		svc := NewAuthService(
			&fakeAuthRepository{
				getUserByEmailFn: func(context.Context, string) (repository.User, error) {
					return repository.User{ID: userID, Email: "user@example.com", PasswordHash: "stored_hash", DisplayName: "user_name", Role: "user", AvatarMetadata: json.RawMessage("{}")}, nil
				},
				rotateSessionFn: func(context.Context, repository.RotateSessionParams) (repository.Session, error) {
					return repository.Session{ID: mustUUIDForServiceTest(t), UserID: userID, ExpiresAt: time.Now().UTC().Add(time.Hour)}, nil
				},
			},
			&fakePasswordHasher{verifyFn: func(password, encodedHash string) (bool, error) {
				return password == "Str0ngPassw0rd!" && encodedHash == "stored_hash", nil
			}},
			&fakeAuthEmailSender{},
			nil,
			nil,
			defaultAuthServiceConfig(),
		)

		result, err := svc.Login(t.Context(), LoginInput{Email: "user@example.com", Password: "Str0ngPassw0rd!"})
		if err != nil {
			t.Fatalf("login returned error: %v", err)
		}

		if result.User.ID != userID {
			t.Fatalf("unexpected login user id: got=%s expected=%s", result.User.ID, userID)
		}

		if result.Session.Token == "" {
			t.Fatalf("expected session token to be returned")
		}
	})
}

func TestAuthServiceResetPassword(t *testing.T) {
	t.Run("invalid input", func(t *testing.T) {
		svc := NewAuthService(
			&fakeAuthRepository{},
			&fakePasswordHasher{},
			&fakeAuthEmailSender{},
			nil,
			nil,
			defaultAuthServiceConfig(),
		)

		err := svc.ResetPassword(t.Context(), "", "short")
		if !errors.Is(err, ErrInvalidResetPasswordInput) {
			t.Fatalf("expected ErrInvalidResetPasswordInput, got: %v", err)
		}
	})

	t.Run("invalid token mapping", func(t *testing.T) {
		svc := NewAuthService(
			&fakeAuthRepository{
				resetPasswordByTokenFn: func(context.Context, repository.ResetPasswordByTokenParams) error {
					return repository.ErrInvalidEmailToken
				},
			},
			&fakePasswordHasher{hashFn: func(string) (string, error) { return "new_hash", nil }},
			&fakeAuthEmailSender{},
			nil,
			nil,
			defaultAuthServiceConfig(),
		)

		err := svc.ResetPassword(t.Context(), "valid-token", "N3wPassw0rd!")
		if !errors.Is(err, ErrInvalidOrExpiredResetToken) {
			t.Fatalf("expected ErrInvalidOrExpiredResetToken, got: %v", err)
		}
	})
}

func TestAuthServiceResendVerificationEmail(t *testing.T) {
	verifiedAt := time.Now().UTC()

	svc := NewAuthService(
		&fakeAuthRepository{
			getUserByIDFn: func(context.Context, uuid.UUID) (repository.User, error) {
				return repository.User{ID: mustUUIDForServiceTest(t), Email: "user@example.com", EmailVerifiedAt: &verifiedAt}, nil
			},
		},
		&fakePasswordHasher{},
		&fakeAuthEmailSender{},
		nil,
		nil,
		defaultAuthServiceConfig(),
	)

	err := svc.ResendVerificationEmail(t.Context(), mustUUIDForServiceTest(t))
	if err != nil {
		t.Fatalf("expected nil when user already verified, got: %v", err)
	}
}

func TestAuthServiceCreateAvatarUploadURL(t *testing.T) {
	userID := mustUUIDForServiceTest(t)

	testCases := []struct {
		name        string
		service     *AuthService
		input       CreateAvatarUploadURLInput
		expectedErr error
	}{
		{
			name: "storage unavailable",
			service: NewAuthService(
				&fakeAuthRepository{},
				&fakePasswordHasher{},
				&fakeAuthEmailSender{},
				nil,
				nil,
				defaultAuthServiceConfig(),
			),
			input:       CreateAvatarUploadURLInput{UserID: userID, ContentType: "image/png", ContentLength: 1024},
			expectedErr: ErrAvatarStorageUnavailable,
		},
		{
			name: "unsupported content type",
			service: NewAuthService(
				&fakeAuthRepository{},
				&fakePasswordHasher{},
				&fakeAuthEmailSender{},
				nil,
				&fakeAvatarStorage{createPresignedUploadURLFn: func(context.Context, string, string) (client.PresignedUpload, error) {
					return client.PresignedUpload{}, nil
				}},
				defaultAuthServiceConfig(),
			),
			input:       CreateAvatarUploadURLInput{UserID: userID, ContentType: "image/gif", ContentLength: 1024},
			expectedErr: ErrUnsupportedAvatarContentType,
		},
		{
			name: "file too large",
			service: NewAuthService(
				&fakeAuthRepository{},
				&fakePasswordHasher{},
				&fakeAuthEmailSender{},
				nil,
				&fakeAvatarStorage{createPresignedUploadURLFn: func(context.Context, string, string) (client.PresignedUpload, error) {
					return client.PresignedUpload{}, nil
				}},
				defaultAuthServiceConfig(),
			),
			input:       CreateAvatarUploadURLInput{UserID: userID, ContentType: "image/png", ContentLength: maxAvatarUploadBytes + 1},
			expectedErr: ErrAvatarFileTooLarge,
		},
	}

	for _, testCase := range testCases {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			_, err := testCase.service.CreateAvatarUploadURL(t.Context(), testCase.input)
			if !errors.Is(err, testCase.expectedErr) {
				t.Fatalf("expected %v, got: %v", testCase.expectedErr, err)
			}
		})
	}

	t.Run("success", func(t *testing.T) {
		svc := NewAuthService(
			&fakeAuthRepository{},
			&fakePasswordHasher{},
			&fakeAuthEmailSender{},
			nil,
			&fakeAvatarStorage{createPresignedUploadURLFn: func(_ context.Context, objectKey, contentType string) (client.PresignedUpload, error) {
				return client.PresignedUpload{
					URL:       "https://upload.example.com",
					Method:    "PUT",
					ObjectKey: objectKey,
					ExpiresAt: time.Now().UTC().Add(10 * time.Minute),
					Headers:   map[string]string{"Content-Type": contentType},
				}, nil
			}},
			defaultAuthServiceConfig(),
		)

		result, err := svc.CreateAvatarUploadURL(t.Context(), CreateAvatarUploadURLInput{
			UserID:        userID,
			ContentType:   "image/png",
			ContentLength: 1024,
		})
		if err != nil {
			t.Fatalf("create avatar upload url returned error: %v", err)
		}

		if result.UploadURL == "" || result.ObjectKey == "" {
			t.Fatalf("expected upload url and object key to be populated")
		}
	})
}

func TestAuthServiceConfirmAvatarUploadInvalidMagicBytes(t *testing.T) {
	userID := mustUUIDForServiceTest(t)

	svc := NewAuthService(
		&fakeAuthRepository{},
		&fakePasswordHasher{},
		&fakeAuthEmailSender{},
		nil,
		&fakeAvatarStorage{
			headObjectFn: func(context.Context, string) (client.ObjectMetadata, error) {
				return client.ObjectMetadata{ContentType: "image/png", ContentLength: 1024}, nil
			},
			readObjectPrefixFn: func(context.Context, string, int64) ([]byte, error) {
				return []byte("not-a-real-png-signature"), nil
			},
		},
		defaultAuthServiceConfig(),
	)

	_, err := svc.ConfirmAvatarUpload(t.Context(), ConfirmAvatarUploadInput{
		UserID:    userID,
		ObjectKey: "users/" + userID.String() + "/avatars/avatar.png",
	})
	if !errors.Is(err, ErrInvalidAvatarFileContent) {
		t.Fatalf("expected ErrInvalidAvatarFileContent, got: %v", err)
	}
}

func mustUUIDForServiceTest(t *testing.T) uuid.UUID {
	t.Helper()

	id, err := uuid.NewV7()
	if err != nil {
		t.Fatalf("generate uuidv7: %v", err)
	}

	return id
}

func defaultAuthServiceConfig() AuthServiceConfig {
	return AuthServiceConfig{
		SessionTTL:            time.Hour,
		SessionRefreshWindow:  time.Minute,
		PasswordResetTokenTTL: time.Hour,
		EmailVerificationTTL:  time.Hour,
		AvatarUploadURLTTL:    time.Minute,
	}
}
