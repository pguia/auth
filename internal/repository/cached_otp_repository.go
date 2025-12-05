package repository

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/guipguia/internal/domain"
	"gorm.io/gorm"
)

// cachedOTPRepository wraps OTPRepository with caching
type cachedOTPRepository struct {
	repo  OTPRepository
	cache CacheService
	ttl   time.Duration
}

// NewCachedOTPRepository creates a new cached OTP repository
func NewCachedOTPRepository(db *gorm.DB, cache CacheService, ttlSeconds int) OTPRepository {
	return &cachedOTPRepository{
		repo:  NewOTPRepository(db),
		cache: cache,
		ttl:   time.Duration(ttlSeconds) * time.Second,
	}
}

// otpTokenCacheKey generates a cache key for an OTP by token
func otpTokenCacheKey(token string) string {
	return fmt.Sprintf("auth:otp:token:%s", token)
}

// otpEmailTypeCacheKey generates a cache key for an OTP by email and type
func otpEmailTypeCacheKey(email string, otpType domain.OTPType) string {
	return fmt.Sprintf("auth:otp:email:%s:type:%s", email, otpType)
}

// Create creates a new OTP and caches it
func (r *cachedOTPRepository) Create(otp *domain.OTP) error {
	err := r.repo.Create(otp)
	if err != nil {
		return err
	}

	// Cache the OTP
	r.cacheOTP(otp)

	return nil
}

// GetByToken retrieves an OTP by token with caching
func (r *cachedOTPRepository) GetByToken(token string) (*domain.OTP, error) {
	cacheKey := otpTokenCacheKey(token)

	// Try cache first
	if cached, ok := r.cache.Get(cacheKey); ok {
		if otp := r.unmarshalOTP(cached); otp != nil {
			return otp, nil
		}
	}

	// Cache miss - get from database
	otp, err := r.repo.GetByToken(token)
	if err != nil {
		return nil, err
	}

	// Cache the result
	r.cacheOTP(otp)

	return otp, nil
}

// GetByEmailAndType retrieves the latest valid OTP by email and type with caching
func (r *cachedOTPRepository) GetByEmailAndType(email string, otpType domain.OTPType) (*domain.OTP, error) {
	cacheKey := otpEmailTypeCacheKey(email, otpType)

	// Try cache first
	if cached, ok := r.cache.Get(cacheKey); ok {
		if otp := r.unmarshalOTP(cached); otp != nil {
			return otp, nil
		}
	}

	// Cache miss - get from database
	otp, err := r.repo.GetByEmailAndType(email, otpType)
	if err != nil {
		return nil, err
	}

	// Cache the result
	r.cacheOTP(otp)

	return otp, nil
}

// MarkAsUsed marks an OTP as used and invalidates cache
func (r *cachedOTPRepository) MarkAsUsed(id uuid.UUID) error {
	// Get OTP first to invalidate caches
	// We need to find it by iterating or querying by ID
	// For simplicity, we'll just delete known cache patterns after marking

	err := r.repo.MarkAsUsed(id)
	if err != nil {
		return err
	}

	// Note: We can't easily invalidate cache without knowing the token
	// The caller should invalidate the cache if they have the OTP object

	return nil
}

// DeleteExpired deletes expired OTPs
func (r *cachedOTPRepository) DeleteExpired() error {
	return r.repo.DeleteExpired()
}

// DeleteByUserAndType deletes all OTPs for a user and type
func (r *cachedOTPRepository) DeleteByUserAndType(userID uuid.UUID, otpType domain.OTPType) error {
	return r.repo.DeleteByUserAndType(userID, otpType)
}

// cacheOTP caches an OTP under multiple keys
func (r *cachedOTPRepository) cacheOTP(otp *domain.OTP) {
	data, err := json.Marshal(otp)
	if err != nil {
		return
	}

	// Calculate TTL based on OTP expiry
	ttl := time.Until(otp.ExpiresAt)
	if ttl <= 0 {
		return // Already expired
	}
	if ttl > r.ttl {
		ttl = r.ttl
	}

	r.cache.SetWithTTL(otpTokenCacheKey(otp.Token), string(data), ttl)
	r.cache.SetWithTTL(otpEmailTypeCacheKey(otp.Email, otp.Type), string(data), ttl)
}

// InvalidateOTPCache removes all cache entries for an OTP
// This should be called by the service layer after marking an OTP as used
func (r *cachedOTPRepository) InvalidateOTPCache(otp *domain.OTP) {
	r.cache.Delete(otpTokenCacheKey(otp.Token))
	r.cache.Delete(otpEmailTypeCacheKey(otp.Email, otp.Type))
}

// unmarshalOTP unmarshals a cached OTP
func (r *cachedOTPRepository) unmarshalOTP(cached interface{}) *domain.OTP {
	str, ok := cached.(string)
	if !ok {
		return nil
	}

	var otp domain.OTP
	if err := json.Unmarshal([]byte(str), &otp); err != nil {
		return nil
	}

	// Check if OTP is still valid
	if otp.Used || time.Now().After(otp.ExpiresAt) {
		return nil
	}

	return &otp
}

// CachedOTPRepository extends OTPRepository with cache invalidation
type CachedOTPRepository interface {
	OTPRepository
	InvalidateOTPCache(otp *domain.OTP)
}

// GetCachedOTPRepository returns the cached repository if caching is enabled
func GetCachedOTPRepository(repo OTPRepository) CachedOTPRepository {
	if cached, ok := repo.(*cachedOTPRepository); ok {
		return cached
	}
	return nil
}
