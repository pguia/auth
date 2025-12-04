package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	authv1 "github.com/pguia/auth/api/proto/auth/v1"
	"github.com/pguia/auth/internal/domain"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// Test: Successful User Registration
func TestAuthService_Register_Success(t *testing.T) {
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
		userRepo,
		sessionRepo,
		otpRepo,
		passwordService,
		totpService,
		passwordlessService,
		oauthService,
		jwtService,
		emailService,
	)

	// Mock expectations
	passwordService.On("ValidatePasswordStrength", "SecurePass123!").Return(nil)
	userRepo.On("GetByEmail", "test@example.com").Return(nil, errors.New("user not found"))
	passwordService.On("HashPassword", "SecurePass123!").Return("hashedpassword", nil)
	userRepo.On("Create", mock.AnythingOfType("*domain.User")).Return(nil).Run(func(args mock.Arguments) {
		user := args.Get(0).(*domain.User)
		user.ID = uuid.New()
	})
	otpRepo.On("Create", mock.AnythingOfType("*domain.OTP")).Return(nil).Run(func(args mock.Arguments) {
		otp := args.Get(0).(*domain.OTP)
		otp.ID = uuid.New()
		otp.Token = "verification-token"
	})
	emailService.On("SendVerificationEmail", "test@example.com", mock.Anything).Return(nil)

	// Register user
	req := &authv1.RegisterRequest{
		Email:     "test@example.com",
		Password:  "SecurePass123!",
		FirstName: "John",
		LastName:  "Doe",
		Metadata:  map[string]string{"source": "web"},
	}

	resp, err := service.Register(context.Background(), req)

	// Assert
	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.NotEmpty(t, resp.UserId)
	assert.Equal(t, "test@example.com", resp.Email)
	assert.False(t, resp.EmailVerified)
	assert.Contains(t, resp.Message, "Registration successful")

	userRepo.AssertExpectations(t)
	passwordService.AssertExpectations(t)
	otpRepo.AssertExpectations(t)
	emailService.AssertExpectations(t)
}

// Test: Registration with Existing Email
func TestAuthService_Register_EmailExists(t *testing.T) {
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
		userRepo,
		sessionRepo,
		otpRepo,
		passwordService,
		totpService,
		passwordlessService,
		oauthService,
		jwtService,
		emailService,
	)

	existingUser := &domain.User{
		ID:    uuid.New(),
		Email: "test@example.com",
	}

	// Mock expectations
	passwordService.On("ValidatePasswordStrength", "SecurePass123!").Return(nil)
	userRepo.On("GetByEmail", "test@example.com").Return(existingUser, nil)

	// Register user
	req := &authv1.RegisterRequest{
		Email:     "test@example.com",
		Password:  "SecurePass123!",
		FirstName: "John",
		LastName:  "Doe",
	}

	resp, err := service.Register(context.Background(), req)

	// Assert
	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "already exists")

	userRepo.AssertExpectations(t)
	passwordService.AssertExpectations(t)
}

// Test: Registration with Weak Password
func TestAuthService_Register_WeakPassword(t *testing.T) {
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
		userRepo,
		sessionRepo,
		otpRepo,
		passwordService,
		totpService,
		passwordlessService,
		oauthService,
		jwtService,
		emailService,
	)

	// Mock expectations
	passwordService.On("ValidatePasswordStrength", "weak").Return(errors.New("password too weak"))

	// Register user
	req := &authv1.RegisterRequest{
		Email:     "test@example.com",
		Password:  "weak",
		FirstName: "John",
		LastName:  "Doe",
	}

	resp, err := service.Register(context.Background(), req)

	// Assert
	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "password validation failed")

	passwordService.AssertExpectations(t)
}

// Test: Successful Login without 2FA
func TestAuthService_Login_Success(t *testing.T) {
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
		userRepo,
		sessionRepo,
		otpRepo,
		passwordService,
		totpService,
		passwordlessService,
		oauthService,
		jwtService,
		emailService,
	)

	userID := uuid.New()
	user := &domain.User{
		ID:               userID,
		Email:            "test@example.com",
		PasswordHash:     "hashedpassword",
		TwoFactorEnabled: false,
		EmailVerified:    true,
	}

	// Mock expectations
	userRepo.On("GetByEmail", "test@example.com").Return(user, nil)
	passwordService.On("VerifyPassword", "hashedpassword", "SecurePass123!").Return(nil)
	jwtService.On("GenerateAccessToken", userID, "test@example.com", mock.Anything).Return("access-token", nil)
	jwtService.On("GenerateRefreshToken", userID, "test@example.com").Return("refresh-token", nil)
	sessionRepo.On("Create", mock.AnythingOfType("*domain.Session")).Return(nil).Run(func(args mock.Arguments) {
		session := args.Get(0).(*domain.Session)
		session.ID = uuid.New()
	})
	userRepo.On("UpdateLastLogin", userID).Return(nil)

	// Login
	req := &authv1.LoginRequest{
		Email:      "test@example.com",
		Password:   "SecurePass123!",
		DeviceId:   "device-123",
		DeviceName: "iPhone 12",
	}

	resp, err := service.Login(context.Background(), req)

	// Assert
	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, "access-token", resp.AccessToken)
	assert.Equal(t, "refresh-token", resp.RefreshToken)
	assert.False(t, resp.Requires_2Fa)
	assert.NotEmpty(t, resp.SessionId)
	assert.NotNil(t, resp.User)

	userRepo.AssertExpectations(t)
	passwordService.AssertExpectations(t)
	jwtService.AssertExpectations(t)
	sessionRepo.AssertExpectations(t)
}

// Test: Login with Invalid Credentials
func TestAuthService_Login_InvalidCredentials(t *testing.T) {
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
		userRepo,
		sessionRepo,
		otpRepo,
		passwordService,
		totpService,
		passwordlessService,
		oauthService,
		jwtService,
		emailService,
	)

	// Mock expectations
	userRepo.On("GetByEmail", "test@example.com").Return(nil, errors.New("user not found"))

	// Login
	req := &authv1.LoginRequest{
		Email:    "test@example.com",
		Password: "WrongPassword",
	}

	resp, err := service.Login(context.Background(), req)

	// Assert
	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "invalid credentials")

	userRepo.AssertExpectations(t)
}

// Test: Login with 2FA Required
func TestAuthService_Login_2FARequired(t *testing.T) {
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
		userRepo,
		sessionRepo,
		otpRepo,
		passwordService,
		totpService,
		passwordlessService,
		oauthService,
		jwtService,
		emailService,
	)

	userID := uuid.New()
	user := &domain.User{
		ID:               userID,
		Email:            "test@example.com",
		PasswordHash:     "hashedpassword",
		TwoFactorEnabled: true,
		TwoFactorSecret:  "secret",
	}

	// Mock expectations
	userRepo.On("GetByEmail", "test@example.com").Return(user, nil)
	passwordService.On("VerifyPassword", "hashedpassword", "SecurePass123!").Return(nil)

	// Login without TOTP code
	req := &authv1.LoginRequest{
		Email:    "test@example.com",
		Password: "SecurePass123!",
	}

	resp, err := service.Login(context.Background(), req)

	// Assert
	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.True(t, resp.Requires_2Fa)
	assert.NotEmpty(t, resp.SessionId)
	assert.Empty(t, resp.AccessToken)

	userRepo.AssertExpectations(t)
	passwordService.AssertExpectations(t)
}

// Test: Successful Token Refresh
func TestAuthService_RefreshToken_Success(t *testing.T) {
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
		userRepo,
		sessionRepo,
		otpRepo,
		passwordService,
		totpService,
		passwordlessService,
		oauthService,
		jwtService,
		emailService,
	)

	sessionID := uuid.New()
	userID := uuid.New()
	session := &domain.Session{
		ID:           sessionID,
		UserID:       userID,
		RefreshToken: "refresh-token",
		ExpiresAt:    time.Now().Add(7 * 24 * time.Hour),
	}

	user := &domain.User{
		ID:            userID,
		Email:         "test@example.com",
		EmailVerified: true,
	}

	// Mock expectations
	sessionRepo.On("GetByRefreshToken", "refresh-token").Return(session, nil)
	userRepo.On("GetByID", userID).Return(user, nil)
	jwtService.On("GenerateAccessToken", userID, "test@example.com", mock.Anything).Return("new-access-token", nil)
	jwtService.On("GenerateRefreshToken", userID, "test@example.com").Return("new-refresh-token", nil)
	sessionRepo.On("Update", mock.AnythingOfType("*domain.Session")).Return(nil)

	// Refresh token
	req := &authv1.RefreshTokenRequest{
		RefreshToken: "refresh-token",
	}

	resp, err := service.RefreshToken(context.Background(), req)

	// Assert
	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, "new-access-token", resp.AccessToken)

	sessionRepo.AssertExpectations(t)
	userRepo.AssertExpectations(t)
	jwtService.AssertExpectations(t)
}

// Test: Refresh Token with Invalid Token
func TestAuthService_RefreshToken_InvalidToken(t *testing.T) {
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
		userRepo,
		sessionRepo,
		otpRepo,
		passwordService,
		totpService,
		passwordlessService,
		oauthService,
		jwtService,
		emailService,
	)

	// Mock expectations
	sessionRepo.On("GetByRefreshToken", "invalid-token").Return(nil, errors.New("session not found"))

	// Refresh token
	req := &authv1.RefreshTokenRequest{
		RefreshToken: "invalid-token",
	}

	resp, err := service.RefreshToken(context.Background(), req)

	// Assert
	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "invalid refresh token")

	sessionRepo.AssertExpectations(t)
}
