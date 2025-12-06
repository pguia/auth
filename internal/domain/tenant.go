package domain

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// TenantStatus represents the status of a tenant
type TenantStatus string

const (
	TenantStatusActive    TenantStatus = "active"
	TenantStatusSuspended TenantStatus = "suspended"
	TenantStatusPending   TenantStatus = "pending"
)

// Tenant represents an organization/tenant in the multi-tenant system
type Tenant struct {
	ID          uuid.UUID      `gorm:"type:uuid;primary_key;default:gen_random_uuid()" json:"id"`
	Name        string         `gorm:"not null" json:"name"`
	Slug        string         `gorm:"uniqueIndex;not null" json:"slug"`
	Status      TenantStatus   `gorm:"type:varchar(50);default:'active';not null" json:"status"`
	Domain      string         `gorm:"index" json:"domain,omitempty"`          // Optional: for domain-based tenant resolution
	Settings    JSONMap        `gorm:"type:jsonb;default:'{}'" json:"settings"` // Tenant-specific settings
	CreatedAt   time.Time      `gorm:"autoCreateTime" json:"created_at"`
	UpdatedAt   time.Time      `gorm:"autoUpdateTime" json:"updated_at"`
	DeletedAt   gorm.DeletedAt `gorm:"index" json:"-"`
}

// TableName specifies the table name for Tenant model
func (Tenant) TableName() string {
	return "tenants"
}

// IsActive checks if the tenant is active
func (t *Tenant) IsActive() bool {
	return t.Status == TenantStatusActive
}

// BeforeCreate hook to generate UUID if not set
func (t *Tenant) BeforeCreate(tx *gorm.DB) error {
	if t.ID == uuid.Nil {
		t.ID = uuid.New()
	}
	if t.Status == "" {
		t.Status = TenantStatusActive
	}
	return nil
}

// JSONMap is a helper type for JSONB columns
type JSONMap map[string]interface{}
