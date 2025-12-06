package repository

import (
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/guipguia/internal/domain"
	"gorm.io/gorm"
)

// TenantRepository handles database operations for tenants
type TenantRepository interface {
	Create(tenant *domain.Tenant) error
	GetByID(id uuid.UUID) (*domain.Tenant, error)
	GetBySlug(slug string) (*domain.Tenant, error)
	GetByDomain(domain string) (*domain.Tenant, error)
	Update(tenant *domain.Tenant) error
	Delete(id uuid.UUID) error
	List(limit, offset int) ([]domain.Tenant, int64, error)
	ExistsBySlug(slug string) (bool, error)
}

type tenantRepository struct {
	db *gorm.DB
}

// NewTenantRepository creates a new tenant repository
func NewTenantRepository(db *gorm.DB) TenantRepository {
	return &tenantRepository{db: db}
}

// Create creates a new tenant
func (r *tenantRepository) Create(tenant *domain.Tenant) error {
	return r.db.Create(tenant).Error
}

// GetByID retrieves a tenant by ID
func (r *tenantRepository) GetByID(id uuid.UUID) (*domain.Tenant, error) {
	var tenant domain.Tenant
	err := r.db.First(&tenant, "id = ?", id).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("tenant not found")
		}
		return nil, err
	}
	return &tenant, nil
}

// GetBySlug retrieves a tenant by slug
func (r *tenantRepository) GetBySlug(slug string) (*domain.Tenant, error) {
	var tenant domain.Tenant
	err := r.db.First(&tenant, "slug = ?", slug).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("tenant not found")
		}
		return nil, err
	}
	return &tenant, nil
}

// GetByDomain retrieves a tenant by domain
func (r *tenantRepository) GetByDomain(domainName string) (*domain.Tenant, error) {
	var tenant domain.Tenant
	err := r.db.First(&tenant, "domain = ?", domainName).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("tenant not found")
		}
		return nil, err
	}
	return &tenant, nil
}

// Update updates a tenant
func (r *tenantRepository) Update(tenant *domain.Tenant) error {
	return r.db.Save(tenant).Error
}

// Delete soft deletes a tenant
func (r *tenantRepository) Delete(id uuid.UUID) error {
	result := r.db.Delete(&domain.Tenant{}, "id = ?", id)
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return fmt.Errorf("tenant not found")
	}
	return nil
}

// List retrieves all tenants with pagination
func (r *tenantRepository) List(limit, offset int) ([]domain.Tenant, int64, error) {
	var tenants []domain.Tenant
	var total int64

	// Get total count
	if err := r.db.Model(&domain.Tenant{}).Count(&total).Error; err != nil {
		return nil, 0, err
	}

	// Get paginated results
	err := r.db.Order("created_at DESC").Limit(limit).Offset(offset).Find(&tenants).Error
	if err != nil {
		return nil, 0, err
	}

	return tenants, total, nil
}

// ExistsBySlug checks if a tenant with the given slug exists
func (r *tenantRepository) ExistsBySlug(slug string) (bool, error) {
	var count int64
	err := r.db.Model(&domain.Tenant{}).Where("slug = ?", slug).Count(&count).Error
	if err != nil {
		return false, err
	}
	return count > 0, nil
}
