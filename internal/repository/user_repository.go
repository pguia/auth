package repository

import (
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/guipguia/internal/domain"
	"gorm.io/gorm"
)

// UserRepository handles database operations for users
type UserRepository interface {
	Create(user *domain.User) error
	GetByID(id uuid.UUID) (*domain.User, error)
	GetByEmail(email string) (*domain.User, error)
	Update(user *domain.User) error
	Delete(id uuid.UUID) error
	UpdatePassword(userID uuid.UUID, passwordHash string) error
	VerifyEmail(userID uuid.UUID) error
	Enable2FA(userID uuid.UUID, secret string) error
	Disable2FA(userID uuid.UUID) error
	UpdateLastLogin(userID uuid.UUID) error
	CreateBackupCodes(userID uuid.UUID, codes []string) error
	GetBackupCodes(userID uuid.UUID) ([]domain.BackupCode, error)
	UseBackupCode(userID uuid.UUID, code string) error
	CreateOAuthAccount(account *domain.OAuthAccount) error
	GetOAuthAccount(provider, providerUserID string) (*domain.OAuthAccount, error)
	GetOAuthAccountsByUserID(userID uuid.UUID) ([]domain.OAuthAccount, error)
	DeleteOAuthAccount(userID uuid.UUID, provider string) error
}

type userRepository struct {
	db *gorm.DB
}

// NewUserRepository creates a new user repository
func NewUserRepository(db *gorm.DB) UserRepository {
	return &userRepository{db: db}
}

// Create creates a new user
func (r *userRepository) Create(user *domain.User) error {
	return r.db.Create(user).Error
}

// GetByID retrieves a user by ID
func (r *userRepository) GetByID(id uuid.UUID) (*domain.User, error) {
	var user domain.User
	err := r.db.Preload("OAuthAccounts").First(&user, "id = ?", id).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("user not found")
		}
		return nil, err
	}
	return &user, nil
}

// GetByEmail retrieves a user by email
func (r *userRepository) GetByEmail(email string) (*domain.User, error) {
	var user domain.User
	err := r.db.Preload("OAuthAccounts").First(&user, "email = ?", email).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("user not found")
		}
		return nil, err
	}
	return &user, nil
}

// Update updates a user
func (r *userRepository) Update(user *domain.User) error {
	return r.db.Save(user).Error
}

// Delete soft deletes a user
func (r *userRepository) Delete(id uuid.UUID) error {
	return r.db.Delete(&domain.User{}, "id = ?", id).Error
}

// UpdatePassword updates a user's password hash
func (r *userRepository) UpdatePassword(userID uuid.UUID, passwordHash string) error {
	return r.db.Model(&domain.User{}).Where("id = ?", userID).Update("password_hash", passwordHash).Error
}

// VerifyEmail marks a user's email as verified
func (r *userRepository) VerifyEmail(userID uuid.UUID) error {
	now := gorm.Expr("NOW()")
	return r.db.Model(&domain.User{}).Where("id = ?", userID).Updates(map[string]interface{}{
		"email_verified":    true,
		"email_verified_at": now,
	}).Error
}

// Enable2FA enables 2FA for a user
func (r *userRepository) Enable2FA(userID uuid.UUID, secret string) error {
	return r.db.Model(&domain.User{}).Where("id = ?", userID).Updates(map[string]interface{}{
		"two_factor_enabled": true,
		"two_factor_secret":  secret,
	}).Error
}

// Disable2FA disables 2FA for a user
func (r *userRepository) Disable2FA(userID uuid.UUID) error {
	return r.db.Model(&domain.User{}).Where("id = ?", userID).Updates(map[string]interface{}{
		"two_factor_enabled": false,
		"two_factor_secret":  "",
	}).Error
}

// UpdateLastLogin updates the user's last login timestamp
func (r *userRepository) UpdateLastLogin(userID uuid.UUID) error {
	now := gorm.Expr("NOW()")
	return r.db.Model(&domain.User{}).Where("id = ?", userID).Update("last_login_at", now).Error
}

// CreateBackupCodes creates backup codes for a user
func (r *userRepository) CreateBackupCodes(userID uuid.UUID, codes []string) error {
	// Delete existing backup codes
	if err := r.db.Where("user_id = ?", userID).Delete(&domain.BackupCode{}).Error; err != nil {
		return err
	}

	// Create new backup codes
	backupCodes := make([]domain.BackupCode, len(codes))
	for i, code := range codes {
		backupCodes[i] = domain.BackupCode{
			UserID: userID,
			Code:   code,
		}
	}

	return r.db.Create(&backupCodes).Error
}

// GetBackupCodes retrieves all backup codes for a user
func (r *userRepository) GetBackupCodes(userID uuid.UUID) ([]domain.BackupCode, error) {
	var codes []domain.BackupCode
	err := r.db.Where("user_id = ? AND used = ?", userID, false).Find(&codes).Error
	return codes, err
}

// UseBackupCode marks a backup code as used
func (r *userRepository) UseBackupCode(userID uuid.UUID, code string) error {
	now := gorm.Expr("NOW()")
	result := r.db.Model(&domain.BackupCode{}).
		Where("user_id = ? AND code = ? AND used = ?", userID, code, false).
		Updates(map[string]interface{}{
			"used":    true,
			"used_at": now,
		})

	if result.Error != nil {
		return result.Error
	}

	if result.RowsAffected == 0 {
		return fmt.Errorf("backup code not found or already used")
	}

	return nil
}

// CreateOAuthAccount creates a new OAuth account
func (r *userRepository) CreateOAuthAccount(account *domain.OAuthAccount) error {
	return r.db.Create(account).Error
}

// GetOAuthAccount retrieves an OAuth account by provider and provider user ID
func (r *userRepository) GetOAuthAccount(provider, providerUserID string) (*domain.OAuthAccount, error) {
	var account domain.OAuthAccount
	err := r.db.First(&account, "provider = ? AND provider_user_id = ?", provider, providerUserID).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("oauth account not found")
		}
		return nil, err
	}
	return &account, nil
}

// GetOAuthAccountsByUserID retrieves all OAuth accounts for a user
func (r *userRepository) GetOAuthAccountsByUserID(userID uuid.UUID) ([]domain.OAuthAccount, error) {
	var accounts []domain.OAuthAccount
	err := r.db.Where("user_id = ?", userID).Find(&accounts).Error
	return accounts, err
}

// DeleteOAuthAccount deletes an OAuth account
func (r *userRepository) DeleteOAuthAccount(userID uuid.UUID, provider string) error {
	result := r.db.Where("user_id = ? AND provider = ?", userID, provider).Delete(&domain.OAuthAccount{})
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return fmt.Errorf("oauth account not found")
	}
	return nil
}
