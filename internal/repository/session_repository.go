package repository

import (
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/guipguia/internal/domain"
	"gorm.io/gorm"
)

// SessionRepository handles database operations for sessions
type SessionRepository interface {
	Create(session *domain.Session) error
	GetByID(id uuid.UUID) (*domain.Session, error)
	GetByRefreshToken(token string) (*domain.Session, error)
	GetActiveSessions(userID uuid.UUID) ([]domain.Session, error)
	Update(session *domain.Session) error
	Revoke(sessionID uuid.UUID) error
	RevokeAllUserSessions(userID uuid.UUID) error
	DeleteExpired() error
	UpdateLastAccessed(sessionID uuid.UUID) error
}

type sessionRepository struct {
	db *gorm.DB
}

// NewSessionRepository creates a new session repository
func NewSessionRepository(db *gorm.DB) SessionRepository {
	return &sessionRepository{db: db}
}

// Create creates a new session
func (r *sessionRepository) Create(session *domain.Session) error {
	return r.db.Create(session).Error
}

// GetByID retrieves a session by ID
func (r *sessionRepository) GetByID(id uuid.UUID) (*domain.Session, error) {
	var session domain.Session
	err := r.db.First(&session, "id = ?", id).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("session not found")
		}
		return nil, err
	}
	return &session, nil
}

// GetByRefreshToken retrieves a session by refresh token
func (r *sessionRepository) GetByRefreshToken(token string) (*domain.Session, error) {
	var session domain.Session
	err := r.db.First(&session, "refresh_token = ?", token).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("session not found")
		}
		return nil, err
	}
	return &session, nil
}

// GetActiveSessions retrieves all active sessions for a user
func (r *sessionRepository) GetActiveSessions(userID uuid.UUID) ([]domain.Session, error) {
	var sessions []domain.Session
	err := r.db.Where("user_id = ? AND revoked_at IS NULL AND expires_at > ?", userID, time.Now()).
		Order("last_accessed_at DESC").
		Find(&sessions).Error
	return sessions, err
}

// Update updates a session
func (r *sessionRepository) Update(session *domain.Session) error {
	return r.db.Save(session).Error
}

// Revoke revokes a session
func (r *sessionRepository) Revoke(sessionID uuid.UUID) error {
	now := time.Now()
	result := r.db.Model(&domain.Session{}).
		Where("id = ? AND revoked_at IS NULL", sessionID).
		Update("revoked_at", now)

	if result.Error != nil {
		return result.Error
	}

	if result.RowsAffected == 0 {
		return fmt.Errorf("session not found or already revoked")
	}

	return nil
}

// RevokeAllUserSessions revokes all sessions for a user
func (r *sessionRepository) RevokeAllUserSessions(userID uuid.UUID) error {
	now := time.Now()
	return r.db.Model(&domain.Session{}).
		Where("user_id = ? AND revoked_at IS NULL", userID).
		Update("revoked_at", now).Error
}

// DeleteExpired deletes expired sessions
func (r *sessionRepository) DeleteExpired() error {
	return r.db.Where("expires_at < ?", time.Now()).Delete(&domain.Session{}).Error
}

// UpdateLastAccessed updates the last accessed timestamp
func (r *sessionRepository) UpdateLastAccessed(sessionID uuid.UUID) error {
	now := time.Now()
	return r.db.Model(&domain.Session{}).
		Where("id = ?", sessionID).
		Update("last_accessed_at", now).Error
}
