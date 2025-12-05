package service

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/guipguia/internal/domain"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// Test: Generate Passwordless Token
func TestPasswordlessService_GenerateToken(t *testing.T) {
	otpRepo := new(MockOTPRepository)
	service := NewPasswordlessService(otpRepo)

	otpRepo.On("Create", mock.AnythingOfType("*domain.OTP")).Return(nil).Run(func(args mock.Arguments) {
		otp := args.Get(0).(*domain.OTP)
		otp.ID = uuid.New()
	})

	otp, err := service.GenerateToken("test@example.com")

	assert.NoError(t, err)
	assert.NotNil(t, otp)
	assert.Equal(t, "test@example.com", otp.Email)
	assert.Equal(t, domain.OTPTypePasswordless, otp.Type)
	assert.NotEmpty(t, otp.Token)
	assert.True(t, otp.ExpiresAt.After(time.Now()))
	otpRepo.AssertExpectations(t)
}

// Test: Verify Passwordless Token Valid
func TestPasswordlessService_VerifyToken_Valid(t *testing.T) {
	otpRepo := new(MockOTPRepository)
	service := NewPasswordlessService(otpRepo)

	otpID := uuid.New()
	validOTP := &domain.OTP{
		ID:        otpID,
		Email:     "test@example.com",
		Token:     "valid-token",
		Type:      domain.OTPTypePasswordless,
		Used:      false,
		ExpiresAt: time.Now().Add(15 * time.Minute),
	}

	otpRepo.On("GetByToken", "valid-token").Return(validOTP, nil)
	otpRepo.On("MarkAsUsed", otpID).Return(nil)

	otp, err := service.VerifyToken("valid-token")

	assert.NoError(t, err)
	assert.NotNil(t, otp)
	assert.Equal(t, "test@example.com", otp.Email)
	otpRepo.AssertExpectations(t)
}

// Test: Verify Passwordless Token Invalid Type
func TestPasswordlessService_VerifyToken_WrongType(t *testing.T) {
	otpRepo := new(MockOTPRepository)
	service := NewPasswordlessService(otpRepo)

	wrongTypeOTP := &domain.OTP{
		ID:        uuid.New(),
		Email:     "test@example.com",
		Token:     "token",
		Type:      domain.OTPTypeEmailVerification, // Wrong type
		Used:      false,
		ExpiresAt: time.Now().Add(15 * time.Minute),
	}

	otpRepo.On("GetByToken", "token").Return(wrongTypeOTP, nil)

	otp, err := service.VerifyToken("token")

	assert.Error(t, err)
	assert.Nil(t, otp)
	assert.Contains(t, err.Error(), "invalid token type")
	otpRepo.AssertExpectations(t)
}

// Test: Verify Passwordless Token Expired
func TestPasswordlessService_VerifyToken_Expired(t *testing.T) {
	otpRepo := new(MockOTPRepository)
	service := NewPasswordlessService(otpRepo)

	expiredOTP := &domain.OTP{
		ID:        uuid.New(),
		Email:     "test@example.com",
		Token:     "expired-token",
		Type:      domain.OTPTypePasswordless,
		Used:      false,
		ExpiresAt: time.Now().Add(-1 * time.Hour), // Expired
	}

	otpRepo.On("GetByToken", "expired-token").Return(expiredOTP, nil)

	otp, err := service.VerifyToken("expired-token")

	assert.Error(t, err)
	assert.Nil(t, otp)
	assert.Contains(t, err.Error(), "invalid or expired")
	otpRepo.AssertExpectations(t)
}

// Test: Generate Email Verification Token
func TestGenerateEmailVerificationToken(t *testing.T) {
	otpRepo := new(MockOTPRepository)

	userID := uuid.New()
	email := "test@example.com"

	otpRepo.On("Create", mock.AnythingOfType("*domain.OTP")).Return(nil).Run(func(args mock.Arguments) {
		otp := args.Get(0).(*domain.OTP)
		otp.ID = uuid.New()
		assert.Equal(t, userID, otp.UserID)
		assert.Equal(t, email, otp.Email)
		assert.Equal(t, domain.OTPTypeEmailVerification, otp.Type)
		assert.NotEmpty(t, otp.Token)
	})

	otp, err := GenerateEmailVerificationToken(email, userID, otpRepo)

	assert.NoError(t, err)
	assert.NotNil(t, otp)
	assert.Equal(t, email, otp.Email)
	assert.Equal(t, domain.OTPTypeEmailVerification, otp.Type)
	otpRepo.AssertExpectations(t)
}

// Test: Generate Password Reset Token
func TestGeneratePasswordResetToken(t *testing.T) {
	otpRepo := new(MockOTPRepository)

	userID := uuid.New()
	email := "test@example.com"

	otpRepo.On("Create", mock.AnythingOfType("*domain.OTP")).Return(nil).Run(func(args mock.Arguments) {
		otp := args.Get(0).(*domain.OTP)
		otp.ID = uuid.New()
		assert.Equal(t, userID, otp.UserID)
		assert.Equal(t, email, otp.Email)
		assert.Equal(t, domain.OTPTypePasswordReset, otp.Type)
		assert.NotEmpty(t, otp.Token)
	})

	otp, err := GeneratePasswordResetToken(email, userID, otpRepo)

	assert.NoError(t, err)
	assert.NotNil(t, otp)
	assert.Equal(t, email, otp.Email)
	assert.Equal(t, domain.OTPTypePasswordReset, otp.Type)
	otpRepo.AssertExpectations(t)
}
