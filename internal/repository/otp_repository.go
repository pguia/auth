package repository

import (
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/guipguia/internal/domain"
	"gorm.io/gorm"
)

// OTPRepository handles database operations for OTPs
type OTPRepository interface {
	Create(otp *domain.OTP) error
	GetByToken(tenantID uuid.UUID, token string) (*domain.OTP, error)
	GetByEmailAndType(tenantID uuid.UUID, email string, otpType domain.OTPType) (*domain.OTP, error)
	MarkAsUsed(tenantID, id uuid.UUID) error
	DeleteExpired() error
	DeleteByUserAndType(tenantID, userID uuid.UUID, otpType domain.OTPType) error
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

// GetByToken retrieves an OTP by token within a tenant
func (r *otpRepository) GetByToken(tenantID uuid.UUID, token string) (*domain.OTP, error) {
	var otp domain.OTP
	now := time.Now()
	err := r.db.First(&otp, "tenant_id = ? AND token = ? AND used = ? AND expires_at > ?", tenantID, token, false, now).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("otp not found or expired")
		}
		return nil, err
	}
	return &otp, nil
}

// GetByEmailAndType retrieves the latest valid OTP by email and type within a tenant
func (r *otpRepository) GetByEmailAndType(tenantID uuid.UUID, email string, otpType domain.OTPType) (*domain.OTP, error) {
	var otp domain.OTP
	now := time.Now()
	err := r.db.Where("tenant_id = ? AND email = ? AND type = ? AND used = ? AND expires_at > ?", tenantID, email, otpType, false, now).
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

// MarkAsUsed marks an OTP as used within a tenant
func (r *otpRepository) MarkAsUsed(tenantID, id uuid.UUID) error {
	now := time.Now()
	result := r.db.Model(&domain.OTP{}).
		Where("tenant_id = ? AND id = ? AND used = ?", tenantID, id, false).
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

// DeleteExpired deletes expired OTPs (across all tenants - maintenance task)
func (r *otpRepository) DeleteExpired() error {
	return r.db.Where("expires_at < ?", time.Now()).Delete(&domain.OTP{}).Error
}

// DeleteByUserAndType deletes all OTPs for a user and type within a tenant
func (r *otpRepository) DeleteByUserAndType(tenantID, userID uuid.UUID, otpType domain.OTPType) error {
	return r.db.Where("tenant_id = ? AND user_id = ? AND type = ?", tenantID, userID, otpType).Delete(&domain.OTP{}).Error
}
