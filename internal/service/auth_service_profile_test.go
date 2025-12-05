package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	authv1 "github.com/guipguia/api/proto/auth/v1"
	"github.com/guipguia/internal/domain"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// Test: Verify Email Success
func TestAuthService_VerifyEmail_Success(t *testing.T) {
	userRepo := new(MockUserRepository)
	sessionRepo := new(MockSessionRepository)
	otpRepo := new(MockOTPRepository)
	passwordService := new(MockPasswordService)
	totpService := new(MockTOTPService)
	passwordlessService := new(MockPasswordlessService)
	oauthService := new(MockOAuthService)
	jwtService := new(MockJWTService)
	emailService := new(MockEmailService)

	service := NewAuthService(
		userRepo, sessionRepo, otpRepo, passwordService,
		totpService, passwordlessService, oauthService,
		jwtService, emailService,
	)

	userID := uuid.New()
	otp := &domain.OTP{
		ID:        uuid.New(),
		UserID:    userID,
		Email:     "test@example.com",
		Token:     "verify-token",
		Type:      domain.OTPTypeEmailVerification,
		ExpiresAt: time.Now().Add(24 * time.Hour),
		Used:      false,
	}

	otpRepo.On("GetByToken", "verify-token").Return(otp, nil)
	userRepo.On("VerifyEmail", userID).Return(nil)
	otpRepo.On("MarkAsUsed", otp.ID).Return(nil)

	req := &authv1.VerifyEmailRequest{
		Token: "verify-token",
	}

	resp, err := service.VerifyEmail(context.Background(), req)

	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.True(t, resp.Success)
	otpRepo.AssertExpectations(t)
	userRepo.AssertExpectations(t)
}

// Test: Verify Email Invalid Token
func TestAuthService_VerifyEmail_InvalidToken(t *testing.T) {
	userRepo := new(MockUserRepository)
	sessionRepo := new(MockSessionRepository)
	otpRepo := new(MockOTPRepository)
	passwordService := new(MockPasswordService)
	totpService := new(MockTOTPService)
	passwordlessService := new(MockPasswordlessService)
	oauthService := new(MockOAuthService)
	jwtService := new(MockJWTService)
	emailService := new(MockEmailService)

	service := NewAuthService(
		userRepo, sessionRepo, otpRepo, passwordService,
		totpService, passwordlessService, oauthService,
		jwtService, emailService,
	)

	otpRepo.On("GetByToken", "invalid-token").Return(nil, errors.New("token not found"))

	req := &authv1.VerifyEmailRequest{
		Token: "invalid-token",
	}

	resp, err := service.VerifyEmail(context.Background(), req)

	assert.Error(t, err)
	assert.Nil(t, resp)
	otpRepo.AssertExpectations(t)
}

// Test: Resend Verification Email
func TestAuthService_ResendVerificationEmail_Success(t *testing.T) {
	userRepo := new(MockUserRepository)
	sessionRepo := new(MockSessionRepository)
	otpRepo := new(MockOTPRepository)
	passwordService := new(MockPasswordService)
	totpService := new(MockTOTPService)
	passwordlessService := new(MockPasswordlessService)
	oauthService := new(MockOAuthService)
	jwtService := new(MockJWTService)
	emailService := new(MockEmailService)

	service := NewAuthService(
		userRepo, sessionRepo, otpRepo, passwordService,
		totpService, passwordlessService, oauthService,
		jwtService, emailService,
	)

	userID := uuid.New()
	user := &domain.User{
		ID:            userID,
		Email:         "test@example.com",
		EmailVerified: false,
	}

	userRepo.On("GetByEmail", "test@example.com").Return(user, nil)
	otpRepo.On("Create", mock.AnythingOfType("*domain.OTP")).Return(nil).Run(func(args mock.Arguments) {
		otp := args.Get(0).(*domain.OTP)
		otp.ID = uuid.New()
		otp.Token = "new-verify-token"
	})
	emailService.On("SendVerificationEmail", "test@example.com", mock.Anything).Return(nil)

	req := &authv1.ResendVerificationEmailRequest{
		Email: "test@example.com",
	}

	resp, err := service.ResendVerificationEmail(context.Background(), req)

	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.True(t, resp.Success)
	userRepo.AssertExpectations(t)
	otpRepo.AssertExpectations(t)
	emailService.AssertExpectations(t)
}

// Test: Get User Profile
func TestAuthService_GetUserProfile_Success(t *testing.T) {
	userRepo := new(MockUserRepository)
	sessionRepo := new(MockSessionRepository)
	otpRepo := new(MockOTPRepository)
	passwordService := new(MockPasswordService)
	totpService := new(MockTOTPService)
	passwordlessService := new(MockPasswordlessService)
	oauthService := new(MockOAuthService)
	jwtService := new(MockJWTService)
	emailService := new(MockEmailService)

	service := NewAuthService(
		userRepo, sessionRepo, otpRepo, passwordService,
		totpService, passwordlessService, oauthService,
		jwtService, emailService,
	)

	userID := uuid.New()
	user := &domain.User{
		ID:            userID,
		Email:         "test@example.com",
		FirstName:     "John",
		LastName:      "Doe",
		EmailVerified: true,
	}

	userRepo.On("GetByID", userID).Return(user, nil)

	req := &authv1.GetUserProfileRequest{
		UserId: userID.String(),
	}

	resp, err := service.GetUserProfile(context.Background(), req)

	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.NotNil(t, resp.User)
	assert.Equal(t, "test@example.com", resp.User.Email)
	userRepo.AssertExpectations(t)
}

// Test: Update User Profile
func TestAuthService_UpdateUserProfile_Success(t *testing.T) {
	userRepo := new(MockUserRepository)
	sessionRepo := new(MockSessionRepository)
	otpRepo := new(MockOTPRepository)
	passwordService := new(MockPasswordService)
	totpService := new(MockTOTPService)
	passwordlessService := new(MockPasswordlessService)
	oauthService := new(MockOAuthService)
	jwtService := new(MockJWTService)
	emailService := new(MockEmailService)

	service := NewAuthService(
		userRepo, sessionRepo, otpRepo, passwordService,
		totpService, passwordlessService, oauthService,
		jwtService, emailService,
	)

	userID := uuid.New()
	user := &domain.User{
		ID:        userID,
		Email:     "test@example.com",
		FirstName: "John",
		LastName:  "Doe",
	}

	userRepo.On("GetByID", userID).Return(user, nil)
	userRepo.On("Update", mock.AnythingOfType("*domain.User")).Return(nil)

	req := &authv1.UpdateUserProfileRequest{
		UserId:      userID.String(),
		FirstName:   "Jane",
		LastName:    "Smith",
		PhoneNumber: "+1234567890",
		Metadata:    map[string]string{"country": "US"},
	}

	resp, err := service.UpdateUserProfile(context.Background(), req)

	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.NotNil(t, resp.User)
	userRepo.AssertExpectations(t)
}

// Test: Get Active Sessions
func TestAuthService_GetActiveSessions_Success(t *testing.T) {
	userRepo := new(MockUserRepository)
	sessionRepo := new(MockSessionRepository)
	otpRepo := new(MockOTPRepository)
	passwordService := new(MockPasswordService)
	totpService := new(MockTOTPService)
	passwordlessService := new(MockPasswordlessService)
	oauthService := new(MockOAuthService)
	jwtService := new(MockJWTService)
	emailService := new(MockEmailService)

	service := NewAuthService(
		userRepo, sessionRepo, otpRepo, passwordService,
		totpService, passwordlessService, oauthService,
		jwtService, emailService,
	)

	userID := uuid.New()
	sessions := []domain.Session{
		{
			ID:         uuid.New(),
			UserID:     userID,
			DeviceName: "iPhone 12",
			ExpiresAt:  time.Now().Add(7 * 24 * time.Hour),
		},
		{
			ID:         uuid.New(),
			UserID:     userID,
			DeviceName: "Chrome Browser",
			ExpiresAt:  time.Now().Add(7 * 24 * time.Hour),
		},
	}

	sessionRepo.On("GetActiveSessions", userID).Return(sessions, nil)

	req := &authv1.GetActiveSessionsRequest{
		UserId: userID.String(),
	}

	resp, err := service.GetActiveSessions(context.Background(), req)

	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Len(t, resp.Sessions, 2)
	sessionRepo.AssertExpectations(t)
}

// Test: Revoke Session
func TestAuthService_RevokeSession_Success(t *testing.T) {
	userRepo := new(MockUserRepository)
	sessionRepo := new(MockSessionRepository)
	otpRepo := new(MockOTPRepository)
	passwordService := new(MockPasswordService)
	totpService := new(MockTOTPService)
	passwordlessService := new(MockPasswordlessService)
	oauthService := new(MockOAuthService)
	jwtService := new(MockJWTService)
	emailService := new(MockEmailService)

	service := NewAuthService(
		userRepo, sessionRepo, otpRepo, passwordService,
		totpService, passwordlessService, oauthService,
		jwtService, emailService,
	)

	userID := uuid.New()
	sessionID := uuid.New()
	session := &domain.Session{
		ID:     sessionID,
		UserID: userID,
	}

	sessionRepo.On("GetByID", sessionID).Return(session, nil)
	sessionRepo.On("Revoke", sessionID).Return(nil)

	req := &authv1.RevokeSessionRequest{
		UserId:    userID.String(),
		SessionId: sessionID.String(),
	}

	resp, err := service.RevokeSession(context.Background(), req)

	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.True(t, resp.Success)
	sessionRepo.AssertExpectations(t)
}

// Test: Validate Token Success
func TestAuthService_ValidateToken_Success(t *testing.T) {
	userRepo := new(MockUserRepository)
	sessionRepo := new(MockSessionRepository)
	otpRepo := new(MockOTPRepository)
	passwordService := new(MockPasswordService)
	totpService := new(MockTOTPService)
	passwordlessService := new(MockPasswordlessService)
	oauthService := new(MockOAuthService)
	jwtService := new(MockJWTService)
	emailService := new(MockEmailService)

	service := NewAuthService(
		userRepo, sessionRepo, otpRepo, passwordService,
		totpService, passwordlessService, oauthService,
		jwtService, emailService,
	)

	userID := uuid.New()
	expiresAt := time.Now().Add(15 * time.Minute)
	claims := &Claims{
		UserID: userID.String(),
		Email:  "test@example.com",
		Type:   AccessToken,
		Extra:  make(map[string]string),
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expiresAt),
		},
	}

	jwtService.On("ValidateToken", "valid-token", AccessToken).Return(claims, nil)

	req := &authv1.ValidateTokenRequest{
		AccessToken: "valid-token",
	}

	resp, err := service.ValidateToken(context.Background(), req)

	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.True(t, resp.Valid)
	assert.Equal(t, userID.String(), resp.UserId)
	jwtService.AssertExpectations(t)
}

// Test: Validate Token Invalid
func TestAuthService_ValidateToken_Invalid(t *testing.T) {
	userRepo := new(MockUserRepository)
	sessionRepo := new(MockSessionRepository)
	otpRepo := new(MockOTPRepository)
	passwordService := new(MockPasswordService)
	totpService := new(MockTOTPService)
	passwordlessService := new(MockPasswordlessService)
	oauthService := new(MockOAuthService)
	jwtService := new(MockJWTService)
	emailService := new(MockEmailService)

	service := NewAuthService(
		userRepo, sessionRepo, otpRepo, passwordService,
		totpService, passwordlessService, oauthService,
		jwtService, emailService,
	)

	jwtService.On("ValidateToken", "invalid-token", AccessToken).Return(nil, errors.New("invalid token"))

	req := &authv1.ValidateTokenRequest{
		AccessToken: "invalid-token",
	}

	resp, err := service.ValidateToken(context.Background(), req)

	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.False(t, resp.Valid)
	jwtService.AssertExpectations(t)
}

// Test: Revoke Token
func TestAuthService_RevokeToken_Success(t *testing.T) {
	userRepo := new(MockUserRepository)
	sessionRepo := new(MockSessionRepository)
	otpRepo := new(MockOTPRepository)
	passwordService := new(MockPasswordService)
	totpService := new(MockTOTPService)
	passwordlessService := new(MockPasswordlessService)
	oauthService := new(MockOAuthService)
	jwtService := new(MockJWTService)
	emailService := new(MockEmailService)

	service := NewAuthService(
		userRepo, sessionRepo, otpRepo, passwordService,
		totpService, passwordlessService, oauthService,
		jwtService, emailService,
	)

	sessionRepo.On("GetByRefreshToken", "some-token").Return(&domain.Session{
		ID: uuid.New(),
	}, nil)
	sessionRepo.On("Revoke", mock.AnythingOfType("uuid.UUID")).Return(nil)

	req := &authv1.RevokeTokenRequest{
		Token:     "some-token",
		TokenType: authv1.TokenType_TOKEN_TYPE_REFRESH,
	}

	resp, err := service.RevokeToken(context.Background(), req)

	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.True(t, resp.Success)
	sessionRepo.AssertExpectations(t)
}
