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

// Test: Send Passwordless Email Success
func TestAuthService_SendPasswordlessEmail_Success(t *testing.T) {
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

	otp := &domain.OTP{
		ID:        uuid.New(),
		Email:     "test@example.com",
		Token:     "passwordless-token",
		Type:      domain.OTPTypePasswordless,
		ExpiresAt: time.Now().Add(15 * time.Minute),
	}

	passwordlessService.On("GenerateToken", "test@example.com").Return(otp, nil)
	emailService.On("SendPasswordlessEmail", "test@example.com", "passwordless-token").Return(nil)

	req := &authv1.SendPasswordlessEmailRequest{
		Email: "test@example.com",
	}

	resp, err := service.SendPasswordlessEmail(context.Background(), req)

	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.True(t, resp.Success)
	passwordlessService.AssertExpectations(t)
	emailService.AssertExpectations(t)
}

// Test: Send Passwordless Email Failure
func TestAuthService_SendPasswordlessEmail_GenerateTokenFails(t *testing.T) {
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

	passwordlessService.On("GenerateToken", "test@example.com").Return(nil, errors.New("failed to generate"))

	req := &authv1.SendPasswordlessEmailRequest{
		Email: "test@example.com",
	}

	resp, err := service.SendPasswordlessEmail(context.Background(), req)

	assert.Error(t, err)
	assert.Nil(t, resp)
	passwordlessService.AssertExpectations(t)
}

// Test: Verify Passwordless Token Success - New User
func TestAuthService_VerifyPasswordlessToken_Success_NewUser(t *testing.T) {
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

	otp := &domain.OTP{
		ID:        uuid.New(),
		Email:     "newuser@example.com",
		Token:     "passwordless-token",
		Type:      domain.OTPTypePasswordless,
		ExpiresAt: time.Now().Add(15 * time.Minute),
		Used:      false,
	}

	passwordlessService.On("VerifyToken", "passwordless-token").Return(otp, nil)
	userRepo.On("GetByEmail", "newuser@example.com").Return(nil, errors.New("user not found"))
	userRepo.On("Create", mock.AnythingOfType("*domain.User")).Return(nil).Run(func(args mock.Arguments) {
		user := args.Get(0).(*domain.User)
		user.ID = uuid.New()
		user.EmailVerified = true // Mark as verified immediately for passwordless
	})
	jwtService.On("GenerateAccessToken", mock.AnythingOfType("uuid.UUID"), "newuser@example.com", mock.Anything).Return("access-token", nil)
	jwtService.On("GenerateRefreshToken", mock.AnythingOfType("uuid.UUID"), "newuser@example.com").Return("refresh-token", nil)
	sessionRepo.On("Create", mock.AnythingOfType("*domain.Session")).Return(nil).Run(func(args mock.Arguments) {
		session := args.Get(0).(*domain.Session)
		session.ID = uuid.New()
	})
	userRepo.On("UpdateLastLogin", mock.AnythingOfType("uuid.UUID")).Return(nil)

	req := &authv1.VerifyPasswordlessTokenRequest{
		Token:      "passwordless-token",
		DeviceId:   "device-123",
		DeviceName: "Chrome",
	}

	resp, err := service.VerifyPasswordlessToken(context.Background(), req)

	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, "access-token", resp.AccessToken)
	assert.Equal(t, "refresh-token", resp.RefreshToken)
	passwordlessService.AssertExpectations(t)
	userRepo.AssertExpectations(t)
	jwtService.AssertExpectations(t)
	sessionRepo.AssertExpectations(t)
}

// Test: Verify Passwordless Token Success - Existing User
func TestAuthService_VerifyPasswordlessToken_Success_ExistingUser(t *testing.T) {
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
		Email:     "existing@example.com",
		Token:     "passwordless-token",
		Type:      domain.OTPTypePasswordless,
		ExpiresAt: time.Now().Add(15 * time.Minute),
		Used:      false,
	}
	user := &domain.User{
		ID:            userID,
		Email:         "existing@example.com",
		EmailVerified: true,
	}

	passwordlessService.On("VerifyToken", "passwordless-token").Return(otp, nil)
	userRepo.On("GetByEmail", "existing@example.com").Return(user, nil)
	jwtService.On("GenerateAccessToken", userID, "existing@example.com", mock.Anything).Return("access-token", nil)
	jwtService.On("GenerateRefreshToken", userID, "existing@example.com").Return("refresh-token", nil)
	sessionRepo.On("Create", mock.AnythingOfType("*domain.Session")).Return(nil).Run(func(args mock.Arguments) {
		session := args.Get(0).(*domain.Session)
		session.ID = uuid.New()
	})
	userRepo.On("UpdateLastLogin", userID).Return(nil)

	req := &authv1.VerifyPasswordlessTokenRequest{
		Token:      "passwordless-token",
		DeviceId:   "device-123",
		DeviceName: "Chrome",
	}

	resp, err := service.VerifyPasswordlessToken(context.Background(), req)

	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, "access-token", resp.AccessToken)
	passwordlessService.AssertExpectations(t)
	userRepo.AssertExpectations(t)
	jwtService.AssertExpectations(t)
	sessionRepo.AssertExpectations(t)
}

// Test: Verify Passwordless Token Invalid
func TestAuthService_VerifyPasswordlessToken_InvalidToken(t *testing.T) {
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

	passwordlessService.On("VerifyToken", "invalid-token").Return(nil, errors.New("invalid token"))

	req := &authv1.VerifyPasswordlessTokenRequest{
		Token: "invalid-token",
	}

	resp, err := service.VerifyPasswordlessToken(context.Background(), req)

	assert.Error(t, err)
	assert.Nil(t, resp)
	passwordlessService.AssertExpectations(t)
}

// Test: Generate 2FA Backup Codes
func TestAuthService_Generate2FABackupCodes_Success(t *testing.T) {
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
		ID:               userID,
		Email:            "test@example.com",
		PasswordHash:     "hash123",
		TwoFactorEnabled: true,
	}

	userRepo.On("GetByID", userID).Return(user, nil)
	passwordService.On("VerifyPassword", "hash123", "MyPass123!").Return(nil)
	totpService.On("GenerateBackupCodes", 10).Return([]string{"CODE1-1234", "CODE2-5678"}, nil)
	userRepo.On("CreateBackupCodes", userID, []string{"CODE1-1234", "CODE2-5678"}).Return(nil)

	req := &authv1.Generate2FABackupCodesRequest{
		UserId:   userID.String(),
		Password: "MyPass123!",
	}

	resp, err := service.Generate2FABackupCodes(context.Background(), req)

	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Len(t, resp.BackupCodes, 2)
	userRepo.AssertExpectations(t)
	passwordService.AssertExpectations(t)
	totpService.AssertExpectations(t)
}
