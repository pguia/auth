package domain

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// User represents a user in the system
type User struct {
	ID                uuid.UUID       `gorm:"type:uuid;primary_key;default:gen_random_uuid()" json:"id"`
	Email             string          `gorm:"uniqueIndex;not null" json:"email"`
	PasswordHash      string          `gorm:"column:password_hash" json:"-"`
	FirstName         string          `gorm:"column:first_name" json:"first_name"`
	LastName          string          `gorm:"column:last_name" json:"last_name"`
	PhoneNumber       string          `gorm:"column:phone_number" json:"phone_number,omitempty"`
	EmailVerified     bool            `gorm:"default:false" json:"email_verified"`
	EmailVerifiedAt   *time.Time      `gorm:"column:email_verified_at" json:"email_verified_at,omitempty"`
	TwoFactorEnabled  bool            `gorm:"default:false" json:"two_factor_enabled"`
	TwoFactorSecret   string          `gorm:"column:two_factor_secret" json:"-"`
	BackupCodes       []BackupCode    `gorm:"foreignKey:UserID" json:"-"`
	OAuthAccounts     []OAuthAccount  `gorm:"foreignKey:UserID" json:"oauth_accounts,omitempty"`
	Sessions          []Session       `gorm:"foreignKey:UserID" json:"-"`
	Metadata          map[string]string `gorm:"type:jsonb" json:"metadata,omitempty"`
	LastLoginAt       *time.Time      `gorm:"column:last_login_at" json:"last_login_at,omitempty"`
	CreatedAt         time.Time       `gorm:"autoCreateTime" json:"created_at"`
	UpdatedAt         time.Time       `gorm:"autoUpdateTime" json:"updated_at"`
	DeletedAt         gorm.DeletedAt  `gorm:"index" json:"-"`
}

// TableName specifies the table name for User model
func (User) TableName() string {
	return "users"
}

// BackupCode represents a 2FA backup code
type BackupCode struct {
	ID        uuid.UUID      `gorm:"type:uuid;primary_key;default:gen_random_uuid()" json:"id"`
	UserID    uuid.UUID      `gorm:"type:uuid;not null;index" json:"user_id"`
	Code      string         `gorm:"not null" json:"code"`
	Used      bool           `gorm:"default:false" json:"used"`
	UsedAt    *time.Time     `gorm:"column:used_at" json:"used_at,omitempty"`
	CreatedAt time.Time      `gorm:"autoCreateTime" json:"created_at"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"-"`
}

// TableName specifies the table name for BackupCode model
func (BackupCode) TableName() string {
	return "backup_codes"
}

// OAuthAccount represents a linked OAuth provider account
type OAuthAccount struct {
	ID             uuid.UUID      `gorm:"type:uuid;primary_key;default:gen_random_uuid()" json:"id"`
	UserID         uuid.UUID      `gorm:"type:uuid;not null;index" json:"user_id"`
	Provider       string         `gorm:"not null" json:"provider"` // google, github, facebook, apple
	ProviderUserID string         `gorm:"column:provider_user_id;not null" json:"provider_user_id"`
	Email          string         `json:"email"`
	AccessToken    string         `gorm:"column:access_token" json:"-"`
	RefreshToken   string         `gorm:"column:refresh_token" json:"-"`
	ExpiresAt      *time.Time     `gorm:"column:expires_at" json:"expires_at,omitempty"`
	Metadata       map[string]string `gorm:"type:jsonb" json:"metadata,omitempty"`
	LinkedAt       time.Time      `gorm:"column:linked_at;autoCreateTime" json:"linked_at"`
	UpdatedAt      time.Time      `gorm:"autoUpdateTime" json:"updated_at"`
	DeletedAt      gorm.DeletedAt `gorm:"index" json:"-"`
}

// TableName specifies the table name for OAuthAccount model
func (OAuthAccount) TableName() string {
	return "oauth_accounts"
}

// BeforeCreate hook to generate UUID if not set
func (u *User) BeforeCreate(tx *gorm.DB) error {
	if u.ID == uuid.Nil {
		u.ID = uuid.New()
	}
	return nil
}
