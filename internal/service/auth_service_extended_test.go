package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	authv1 "github.com/guipguia/api/proto/auth/v1"
	"github.com/guipguia/internal/domain"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// Test: Successful Logout
func TestAuthService_Logout_Success(t *testing.T) {
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

	sessionID := uuid.New()
	sessionRepo.On("Revoke", sessionID).Return(nil)

	req := &authv1.LogoutRequest{
		SessionId: sessionID.String(),
	}

	resp, err := service.Logout(context.Background(), req)

	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.True(t, resp.Success)
	sessionRepo.AssertExpectations(t)
}

// Test: Change Password Success
func TestAuthService_ChangePassword_Success(t *testing.T) {
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
		ID:           userID,
		Email:        "test@example.com",
		PasswordHash: "old-hash",
	}

	userRepo.On("GetByID", userID).Return(user, nil)
	passwordService.On("VerifyPassword", "old-hash", "OldPass123!").Return(nil)
	passwordService.On("ValidatePasswordStrength", "NewPass123!").Return(nil)
	passwordService.On("HashPassword", "NewPass123!").Return("new-hash", nil)
	userRepo.On("UpdatePassword", userID, "new-hash").Return(nil)
	sessionRepo.On("RevokeAllUserSessions", userID).Return(nil)

	req := &authv1.ChangePasswordRequest{
		UserId:          userID.String(),
		CurrentPassword: "OldPass123!",
		NewPassword:     "NewPass123!",
	}

	resp, err := service.ChangePassword(context.Background(), req)

	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.True(t, resp.Success)
	userRepo.AssertExpectations(t)
	passwordService.AssertExpectations(t)
}

// Test: Change Password with Wrong Current Password
func TestAuthService_ChangePassword_WrongCurrentPassword(t *testing.T) {
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
		ID:           userID,
		Email:        "test@example.com",
		PasswordHash: "old-hash",
	}

	userRepo.On("GetByID", userID).Return(user, nil)
	passwordService.On("VerifyPassword", "old-hash", "WrongPass!").Return(errors.New("invalid password"))

	req := &authv1.ChangePasswordRequest{
		UserId:          userID.String(),
		CurrentPassword: "WrongPass!",
		NewPassword:     "NewPass123!",
	}

	resp, err := service.ChangePassword(context.Background(), req)

	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "invalid current password")
	userRepo.AssertExpectations(t)
	passwordService.AssertExpectations(t)
}

// Test: Forgot Password
func TestAuthService_ForgotPassword_Success(t *testing.T) {
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
		ID:    userID,
		Email: "test@example.com",
	}

	userRepo.On("GetByEmail", "test@example.com").Return(user, nil)
	otpRepo.On("Create", mock.AnythingOfType("*domain.OTP")).Return(nil).Run(func(args mock.Arguments) {
		otp := args.Get(0).(*domain.OTP)
		otp.ID = uuid.New()
		otp.Token = "reset-token"
	})
	emailService.On("SendPasswordResetEmail", "test@example.com", mock.Anything).Return(nil)

	req := &authv1.ForgotPasswordRequest{
		Email: "test@example.com",
	}

	resp, err := service.ForgotPassword(context.Background(), req)

	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.True(t, resp.Success)
	userRepo.AssertExpectations(t)
	otpRepo.AssertExpectations(t)
	emailService.AssertExpectations(t)
}

// Test: Forgot Password with Non-Existent Email
func TestAuthService_ForgotPassword_NonExistentEmail(t *testing.T) {
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

	userRepo.On("GetByEmail", "nonexistent@example.com").Return(nil, errors.New("user not found"))

	req := &authv1.ForgotPasswordRequest{
		Email: "nonexistent@example.com",
	}

	resp, err := service.ForgotPassword(context.Background(), req)

	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.True(t, resp.Success)
	assert.Contains(t, resp.Message, "If an account")
	userRepo.AssertExpectations(t)
}

// Test: Reset Password Success
func TestAuthService_ResetPassword_Success(t *testing.T) {
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
		Token:     "reset-token",
		Type:      domain.OTPTypePasswordReset,
		ExpiresAt: time.Now().Add(1 * time.Hour),
		Used:      false,
	}

	otpRepo.On("GetByToken", "reset-token").Return(otp, nil)
	passwordService.On("ValidatePasswordStrength", "NewPass123!").Return(nil)
	passwordService.On("HashPassword", "NewPass123!").Return("new-hash", nil)
	userRepo.On("UpdatePassword", userID, "new-hash").Return(nil)
	otpRepo.On("MarkAsUsed", otp.ID).Return(nil)
	sessionRepo.On("RevokeAllUserSessions", userID).Return(nil)

	req := &authv1.ResetPasswordRequest{
		Token:       "reset-token",
		NewPassword: "NewPass123!",
	}

	resp, err := service.ResetPassword(context.Background(), req)

	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.True(t, resp.Success)
	otpRepo.AssertExpectations(t)
	passwordService.AssertExpectations(t)
	userRepo.AssertExpectations(t)
}

// Test: Reset Password with Invalid Token
func TestAuthService_ResetPassword_InvalidToken(t *testing.T) {
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

	req := &authv1.ResetPasswordRequest{
		Token:       "invalid-token",
		NewPassword: "NewPass123!",
	}

	resp, err := service.ResetPassword(context.Background(), req)

	assert.Error(t, err)
	assert.Nil(t, resp)
	assert.Contains(t, err.Error(), "invalid or expired token")
	otpRepo.AssertExpectations(t)
}

// Test: Enable 2FA
func TestAuthService_Enable2FA_Success(t *testing.T) {
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
		ID:    userID,
		Email: "test@example.com",
	}

	userRepo.On("GetByID", userID).Return(user, nil)
	totpService.On("GenerateSecret", "test@example.com").Return("secret123", "otpauth://totp/...", nil)
	totpService.On("GenerateBackupCodes", 10).Return([]string{"CODE1-1234", "CODE2-5678"}, nil)
	userRepo.On("CreateBackupCodes", userID, []string{"CODE1-1234", "CODE2-5678"}).Return(nil)
	userRepo.On("Enable2FA", userID, "secret123").Return(nil)

	req := &authv1.Enable2FARequest{
		UserId: userID.String(),
	}

	resp, err := service.Enable2FA(context.Background(), req)

	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, "secret123", resp.Secret)
	assert.Equal(t, "otpauth://totp/...", resp.QrCodeUrl)
	assert.Len(t, resp.BackupCodes, 2)
	userRepo.AssertExpectations(t)
	totpService.AssertExpectations(t)
}

// Test: Verify 2FA
func TestAuthService_Verify2FA_Success(t *testing.T) {
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
		ID:              userID,
		Email:           "test@example.com",
		TwoFactorSecret: "secret123",
	}

	userRepo.On("GetByID", userID).Return(user, nil)
	totpService.On("ValidateCode", "secret123", "123456").Return(true)

	req := &authv1.Verify2FARequest{
		UserId:   userID.String(),
		TotpCode: "123456",
	}

	resp, err := service.Verify2FA(context.Background(), req)

	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.True(t, resp.Verified)
	userRepo.AssertExpectations(t)
	totpService.AssertExpectations(t)
}

// Test: Disable 2FA
func TestAuthService_Disable2FA_Success(t *testing.T) {
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
		TwoFactorSecret:  "secret123",
	}

	userRepo.On("GetByID", userID).Return(user, nil)
	passwordService.On("VerifyPassword", "hash123", "MyPass123!").Return(nil)
	totpService.On("ValidateCode", "secret123", "123456").Return(true)
	userRepo.On("Disable2FA", userID).Return(nil)

	req := &authv1.Disable2FARequest{
		UserId:   userID.String(),
		Password: "MyPass123!",
		TotpCode: "123456",
	}

	resp, err := service.Disable2FA(context.Background(), req)

	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.True(t, resp.Success)
	userRepo.AssertExpectations(t)
	passwordService.AssertExpectations(t)
}
