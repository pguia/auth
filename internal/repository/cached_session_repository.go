package repository

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/guipguia/internal/domain"
	"gorm.io/gorm"
)

// CacheService defines the interface for caching operations
type CacheService interface {
	Get(key string) (interface{}, bool)
	Set(key string, value interface{})
	SetWithTTL(key string, value interface{}, ttl time.Duration)
	Delete(key string)
	Clear()
	Close() error
}

// cachedSessionRepository wraps SessionRepository with caching
type cachedSessionRepository struct {
	repo  SessionRepository
	cache CacheService
	ttl   time.Duration
}

// NewCachedSessionRepository creates a new cached session repository
func NewCachedSessionRepository(db *gorm.DB, cache CacheService, ttlSeconds int) SessionRepository {
	return &cachedSessionRepository{
		repo:  NewSessionRepository(db),
		cache: cache,
		ttl:   time.Duration(ttlSeconds) * time.Second,
	}
}

// sessionCacheKey generates a cache key for a session by ID
func sessionCacheKey(id uuid.UUID) string {
	return fmt.Sprintf("auth:session:id:%s", id.String())
}

// sessionRefreshTokenCacheKey generates a cache key for a session by refresh token
func sessionRefreshTokenCacheKey(token string) string {
	return fmt.Sprintf("auth:session:refresh:%s", token)
}

// userSessionsCacheKey generates a cache key for user's active sessions
func userSessionsCacheKey(userID uuid.UUID) string {
	return fmt.Sprintf("auth:session:user:%s", userID.String())
}

// Create creates a new session and invalidates relevant caches
func (r *cachedSessionRepository) Create(session *domain.Session) error {
	err := r.repo.Create(session)
	if err != nil {
		return err
	}

	// Cache the new session
	r.cacheSession(session)

	// Invalidate user's active sessions cache
	r.cache.Delete(userSessionsCacheKey(session.UserID))

	return nil
}

// GetByID retrieves a session by ID with caching
func (r *cachedSessionRepository) GetByID(id uuid.UUID) (*domain.Session, error) {
	cacheKey := sessionCacheKey(id)

	// Try cache first
	if cached, ok := r.cache.Get(cacheKey); ok {
		if session := r.unmarshalSession(cached); session != nil {
			return session, nil
		}
	}

	// Cache miss - get from database
	session, err := r.repo.GetByID(id)
	if err != nil {
		return nil, err
	}

	// Cache the result
	r.cacheSession(session)

	return session, nil
}

// GetByRefreshToken retrieves a session by refresh token with caching
func (r *cachedSessionRepository) GetByRefreshToken(token string) (*domain.Session, error) {
	cacheKey := sessionRefreshTokenCacheKey(token)

	// Try cache first
	if cached, ok := r.cache.Get(cacheKey); ok {
		if session := r.unmarshalSession(cached); session != nil {
			return session, nil
		}
	}

	// Cache miss - get from database
	session, err := r.repo.GetByRefreshToken(token)
	if err != nil {
		return nil, err
	}

	// Cache the result
	r.cacheSession(session)

	return session, nil
}

// GetActiveSessions retrieves all active sessions for a user with caching
func (r *cachedSessionRepository) GetActiveSessions(userID uuid.UUID) ([]domain.Session, error) {
	cacheKey := userSessionsCacheKey(userID)

	// Try cache first
	if cached, ok := r.cache.Get(cacheKey); ok {
		if sessions := r.unmarshalSessions(cached); sessions != nil {
			return sessions, nil
		}
	}

	// Cache miss - get from database
	sessions, err := r.repo.GetActiveSessions(userID)
	if err != nil {
		return nil, err
	}

	// Cache the result
	if data, err := json.Marshal(sessions); err == nil {
		r.cache.SetWithTTL(cacheKey, string(data), r.ttl)
	}

	return sessions, nil
}

// Update updates a session and invalidates caches
func (r *cachedSessionRepository) Update(session *domain.Session) error {
	err := r.repo.Update(session)
	if err != nil {
		return err
	}

	// Update cache
	r.cacheSession(session)

	// Invalidate user's active sessions cache
	r.cache.Delete(userSessionsCacheKey(session.UserID))

	return nil
}

// Revoke revokes a session and invalidates caches
func (r *cachedSessionRepository) Revoke(sessionID uuid.UUID) error {
	// Get session first to know which caches to invalidate
	session, err := r.repo.GetByID(sessionID)
	if err != nil {
		return err
	}

	err = r.repo.Revoke(sessionID)
	if err != nil {
		return err
	}

	// Invalidate all caches for this session
	r.invalidateSessionCache(session)

	return nil
}

// RevokeAllUserSessions revokes all sessions for a user
func (r *cachedSessionRepository) RevokeAllUserSessions(userID uuid.UUID) error {
	// Get all sessions first to invalidate their caches
	sessions, _ := r.repo.GetActiveSessions(userID)

	err := r.repo.RevokeAllUserSessions(userID)
	if err != nil {
		return err
	}

	// Invalidate all session caches
	for _, session := range sessions {
		r.invalidateSessionCache(&session)
	}

	return nil
}

// DeleteExpired deletes expired sessions
func (r *cachedSessionRepository) DeleteExpired() error {
	return r.repo.DeleteExpired()
}

// UpdateLastAccessed updates the last accessed timestamp
func (r *cachedSessionRepository) UpdateLastAccessed(sessionID uuid.UUID) error {
	err := r.repo.UpdateLastAccessed(sessionID)
	if err != nil {
		return err
	}

	// Invalidate session cache to force refresh on next access
	r.cache.Delete(sessionCacheKey(sessionID))

	return nil
}

// cacheSession caches a session under multiple keys
func (r *cachedSessionRepository) cacheSession(session *domain.Session) {
	data, err := json.Marshal(session)
	if err != nil {
		return
	}

	// Calculate TTL based on session expiry
	ttl := r.ttl
	if time.Until(session.ExpiresAt) < ttl {
		ttl = time.Until(session.ExpiresAt)
	}

	if ttl > 0 {
		r.cache.SetWithTTL(sessionCacheKey(session.ID), string(data), ttl)
		r.cache.SetWithTTL(sessionRefreshTokenCacheKey(session.RefreshToken), string(data), ttl)
	}
}

// invalidateSessionCache removes all cache entries for a session
func (r *cachedSessionRepository) invalidateSessionCache(session *domain.Session) {
	r.cache.Delete(sessionCacheKey(session.ID))
	r.cache.Delete(sessionRefreshTokenCacheKey(session.RefreshToken))
	r.cache.Delete(userSessionsCacheKey(session.UserID))
}

// unmarshalSession unmarshals a cached session
func (r *cachedSessionRepository) unmarshalSession(cached interface{}) *domain.Session {
	str, ok := cached.(string)
	if !ok {
		return nil
	}

	var session domain.Session
	if err := json.Unmarshal([]byte(str), &session); err != nil {
		return nil
	}

	// Check if session is still active
	if !session.IsActive() {
		return nil
	}

	return &session
}

// unmarshalSessions unmarshals cached sessions
func (r *cachedSessionRepository) unmarshalSessions(cached interface{}) []domain.Session {
	str, ok := cached.(string)
	if !ok {
		return nil
	}

	var sessions []domain.Session
	if err := json.Unmarshal([]byte(str), &sessions); err != nil {
		return nil
	}

	return sessions
}
