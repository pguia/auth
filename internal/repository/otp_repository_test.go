package repository

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/guipguia/internal/domain"
	"github.com/stretchr/testify/assert"
)

// Test: NewOTPRepository
func TestNewOTPRepository(t *testing.T) {
	db := setupTestDB(t)
	repo := NewOTPRepository(db)

	assert.NotNil(t, repo)
}

// Test: Create OTP
func TestOTPRepository_Create(t *testing.T) {
	db := setupTestDB(t)
	repo := NewOTPRepository(db)

	otp := &domain.OTP{
		UserID:    uuid.New(),
		Email:     "test@example.com",
		Token:     "token-123",
		Type:      domain.OTPTypeEmailVerification,
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}

	err := repo.Create(otp)

	assert.NoError(t, err)
	assert.NotEqual(t, uuid.Nil, otp.ID)
}

// Test: GetByToken Success
func TestOTPRepository_GetByToken_Success(t *testing.T) {
	db := setupTestDB(t)
	repo := NewOTPRepository(db)

	otp := &domain.OTP{
		UserID:    uuid.New(),
		Email:     "test@example.com",
		Token:     "valid-token",
		Type:      domain.OTPTypeEmailVerification,
		ExpiresAt: time.Now().Add(24 * time.Hour),
		Used:      false,
	}
	err := repo.Create(otp)
	assert.NoError(t, err)

	retrieved, err := repo.GetByToken("valid-token")

	assert.NoError(t, err)
	assert.NotNil(t, retrieved)
	assert.Equal(t, otp.Email, retrieved.Email)
}

// Test: GetByToken Not Found
func TestOTPRepository_GetByToken_NotFound(t *testing.T) {
	db := setupTestDB(t)
	repo := NewOTPRepository(db)

	retrieved, err := repo.GetByToken("nonexistent-token")

	assert.Error(t, err)
	assert.Nil(t, retrieved)
	assert.Contains(t, err.Error(), "otp not found or expired")
}

// Test: GetByToken Expired
func TestOTPRepository_GetByToken_Expired(t *testing.T) {
	db := setupTestDB(t)
	repo := NewOTPRepository(db)

	otp := &domain.OTP{
		UserID:    uuid.New(),
		Email:     "test@example.com",
		Token:     "expired-token",
		Type:      domain.OTPTypeEmailVerification,
		ExpiresAt: time.Now().Add(-1 * time.Hour),
		Used:      false,
	}
	err := repo.Create(otp)
	assert.NoError(t, err)

	retrieved, err := repo.GetByToken("expired-token")

	assert.Error(t, err)
	assert.Nil(t, retrieved)
	assert.Contains(t, err.Error(), "otp not found or expired")
}

// Test: GetByToken Already Used
func TestOTPRepository_GetByToken_Used(t *testing.T) {
	db := setupTestDB(t)
	repo := NewOTPRepository(db)

	otp := &domain.OTP{
		UserID:    uuid.New(),
		Email:     "test@example.com",
		Token:     "used-token",
		Type:      domain.OTPTypeEmailVerification,
		ExpiresAt: time.Now().Add(24 * time.Hour),
		Used:      true,
	}
	err := repo.Create(otp)
	assert.NoError(t, err)

	retrieved, err := repo.GetByToken("used-token")

	assert.Error(t, err)
	assert.Nil(t, retrieved)
}

// Test: GetByEmailAndType Success
func TestOTPRepository_GetByEmailAndType_Success(t *testing.T) {
	db := setupTestDB(t)
	repo := NewOTPRepository(db)

	otp := &domain.OTP{
		UserID:    uuid.New(),
		Email:     "test@example.com",
		Token:     "token-123",
		Type:      domain.OTPTypePasswordReset,
		ExpiresAt: time.Now().Add(1 * time.Hour),
		Used:      false,
	}
	err := repo.Create(otp)
	assert.NoError(t, err)

	retrieved, err := repo.GetByEmailAndType("test@example.com", domain.OTPTypePasswordReset)

	assert.NoError(t, err)
	assert.NotNil(t, retrieved)
	assert.Equal(t, otp.Token, retrieved.Token)
}

// Test: GetByEmailAndType Multiple OTPs Returns Latest
func TestOTPRepository_GetByEmailAndType_ReturnsLatest(t *testing.T) {
	db := setupTestDB(t)
	repo := NewOTPRepository(db)

	userID := uuid.New()

	// Create older OTP
	otp1 := &domain.OTP{
		UserID:    userID,
		Email:     "test@example.com",
		Token:     "old-token",
		Type:      domain.OTPTypePasswordReset,
		ExpiresAt: time.Now().Add(1 * time.Hour),
		Used:      false,
	}
	repo.Create(otp1)

	time.Sleep(10 * time.Millisecond)

	// Create newer OTP
	otp2 := &domain.OTP{
		UserID:    userID,
		Email:     "test@example.com",
		Token:     "new-token",
		Type:      domain.OTPTypePasswordReset,
		ExpiresAt: time.Now().Add(1 * time.Hour),
		Used:      false,
	}
	repo.Create(otp2)

	retrieved, err := repo.GetByEmailAndType("test@example.com", domain.OTPTypePasswordReset)

	assert.NoError(t, err)
	assert.NotNil(t, retrieved)
	assert.Equal(t, "new-token", retrieved.Token)
}

// Test: GetByEmailAndType Not Found
func TestOTPRepository_GetByEmailAndType_NotFound(t *testing.T) {
	db := setupTestDB(t)
	repo := NewOTPRepository(db)

	retrieved, err := repo.GetByEmailAndType("nonexistent@example.com", domain.OTPTypePasswordReset)

	assert.Error(t, err)
	assert.Nil(t, retrieved)
}

// Test: MarkAsUsed
func TestOTPRepository_MarkAsUsed(t *testing.T) {
	db := setupTestDB(t)
	repo := NewOTPRepository(db)

	otp := &domain.OTP{
		UserID:    uuid.New(),
		Email:     "test@example.com",
		Token:     "token-123",
		Type:      domain.OTPTypeEmailVerification,
		ExpiresAt: time.Now().Add(24 * time.Hour),
		Used:      false,
	}
	err := repo.Create(otp)
	assert.NoError(t, err)

	err = repo.MarkAsUsed(otp.ID)

	assert.NoError(t, err)

	// Should not be able to retrieve it anymore
	retrieved, err := repo.GetByToken("token-123")
	assert.Error(t, err)
	assert.Nil(t, retrieved)
}

// Test: DeleteExpired
func TestOTPRepository_DeleteExpired(t *testing.T) {
	db := setupTestDB(t)
	repo := NewOTPRepository(db)

	// Create expired OTP
	expiredOTP := &domain.OTP{
		UserID:    uuid.New(),
		Email:     "test@example.com",
		Token:     "expired-token",
		Type:      domain.OTPTypeEmailVerification,
		ExpiresAt: time.Now().Add(-24 * time.Hour),
		Used:      false,
	}
	repo.Create(expiredOTP)

	// Create valid OTP
	validOTP := &domain.OTP{
		UserID:    uuid.New(),
		Email:     "test@example.com",
		Token:     "valid-token",
		Type:      domain.OTPTypeEmailVerification,
		ExpiresAt: time.Now().Add(24 * time.Hour),
		Used:      false,
	}
	repo.Create(validOTP)

	err := repo.DeleteExpired()

	assert.NoError(t, err)

	// Expired OTP should not be retrievable
	_, err = repo.GetByToken("expired-token")
	assert.Error(t, err)

	// Valid OTP should still be retrievable
	_, err = repo.GetByToken("valid-token")
	assert.NoError(t, err)
}

// Test: DeleteByUserAndType
func TestOTPRepository_DeleteByUserAndType(t *testing.T) {
	db := setupTestDB(t)
	repo := NewOTPRepository(db)

	userID := uuid.New()

	// Create OTP to delete
	otp1 := &domain.OTP{
		UserID:    userID,
		Email:     "test@example.com",
		Token:     "token-1",
		Type:      domain.OTPTypePasswordReset,
		ExpiresAt: time.Now().Add(1 * time.Hour),
		Used:      false,
	}
	repo.Create(otp1)

	// Create OTP of different type (should not be deleted)
	otp2 := &domain.OTP{
		UserID:    userID,
		Email:     "test@example.com",
		Token:     "token-2",
		Type:      domain.OTPTypeEmailVerification,
		ExpiresAt: time.Now().Add(1 * time.Hour),
		Used:      false,
	}
	repo.Create(otp2)

	err := repo.DeleteByUserAndType(userID, domain.OTPTypePasswordReset)

	assert.NoError(t, err)

	// OTP of specified type should be deleted
	_, err = repo.GetByToken("token-1")
	assert.Error(t, err)

	// OTP of different type should still exist
	_, err = repo.GetByToken("token-2")
	assert.NoError(t, err)
}

// Test: Create Multiple OTP Types
func TestOTPRepository_MultipleTypes(t *testing.T) {
	db := setupTestDB(t)
	repo := NewOTPRepository(db)

	userID := uuid.New()
	email := "test@example.com"

	// Create OTPs of different types
	types := []domain.OTPType{
		domain.OTPTypeEmailVerification,
		domain.OTPTypePasswordReset,
		domain.OTPTypePasswordless,
		domain.OTPType2FA,
	}

	for _, otpType := range types {
		otp := &domain.OTP{
			UserID:    userID,
			Email:     email,
			Token:     string(otpType) + "-token",
			Type:      otpType,
			ExpiresAt: time.Now().Add(1 * time.Hour),
			Used:      false,
		}
		err := repo.Create(otp)
		assert.NoError(t, err)
	}

	// Verify each type can be retrieved
	for _, otpType := range types {
		retrieved, err := repo.GetByEmailAndType(email, otpType)
		assert.NoError(t, err)
		assert.NotNil(t, retrieved)
		assert.Equal(t, otpType, retrieved.Type)
	}
}
