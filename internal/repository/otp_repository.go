package repository

import (
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/pguia/auth/internal/domain"
	"gorm.io/gorm"
)

// OTPRepository handles database operations for OTPs
type OTPRepository interface {
	Create(otp *domain.OTP) error
	GetByToken(token string) (*domain.OTP, error)
	GetByEmailAndType(email string, otpType domain.OTPType) (*domain.OTP, error)
	MarkAsUsed(id uuid.UUID) error
	DeleteExpired() error
	DeleteByUserAndType(userID uuid.UUID, otpType domain.OTPType) error
}

type otpRepository struct {
	db *gorm.DB
}

// NewOTPRepository creates a new OTP repository
func NewOTPRepository(db *gorm.DB) OTPRepository {
	return &otpRepository{db: db}
}

// Create creates a new OTP
func (r *otpRepository) Create(otp *domain.OTP) error {
	return r.db.Create(otp).Error
}

// GetByToken retrieves an OTP by token
func (r *otpRepository) GetByToken(token string) (*domain.OTP, error) {
	var otp domain.OTP
	err := r.db.First(&otp, "token = ? AND used = ? AND expires_at > ?", token, false, time.Now()).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("otp not found or expired")
		}
		return nil, err
	}
	return &otp, nil
}

// GetByEmailAndType retrieves the latest valid OTP by email and type
func (r *otpRepository) GetByEmailAndType(email string, otpType domain.OTPType) (*domain.OTP, error) {
	var otp domain.OTP
	err := r.db.Where("email = ? AND type = ? AND used = ? AND expires_at > ?", email, otpType, false, time.Now()).
		Order("created_at DESC").
		First(&otp).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("otp not found or expired")
		}
		return nil, err
	}
	return &otp, nil
}

// MarkAsUsed marks an OTP as used
func (r *otpRepository) MarkAsUsed(id uuid.UUID) error {
	now := time.Now()
	result := r.db.Model(&domain.OTP{}).
		Where("id = ? AND used = ?", id, false).
		Updates(map[string]interface{}{
			"used":    true,
			"used_at": now,
		})

	if result.Error != nil {
		return result.Error
	}

	if result.RowsAffected == 0 {
		return fmt.Errorf("otp not found or already used")
	}

	return nil
}

// DeleteExpired deletes expired OTPs
func (r *otpRepository) DeleteExpired() error {
	return r.db.Where("expires_at < ?", time.Now()).Delete(&domain.OTP{}).Error
}

// DeleteByUserAndType deletes all OTPs for a user and type
func (r *otpRepository) DeleteByUserAndType(userID uuid.UUID, otpType domain.OTPType) error {
	return r.db.Where("user_id = ? AND type = ?", userID, otpType).Delete(&domain.OTP{}).Error
}
