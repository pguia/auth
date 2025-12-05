package service

import (
	"github.com/google/uuid"
	"github.com/guipguia/internal/domain"
	"github.com/stretchr/testify/mock"
	"golang.org/x/oauth2"
)

// MockUserRepository is a mock implementation of UserRepository
type MockUserRepository struct {
	mock.Mock
}

func (m *MockUserRepository) Create(user *domain.User) error {
	args := m.Called(user)
	return args.Error(0)
}

func (m *MockUserRepository) GetByID(id uuid.UUID) (*domain.User, error) {
	args := m.Called(id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.User), args.Error(1)
}

func (m *MockUserRepository) GetByEmail(email string) (*domain.User, error) {
	args := m.Called(email)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.User), args.Error(1)
}

func (m *MockUserRepository) Update(user *domain.User) error {
	args := m.Called(user)
	return args.Error(0)
}

func (m *MockUserRepository) Delete(id uuid.UUID) error {
	args := m.Called(id)
	return args.Error(0)
}

func (m *MockUserRepository) UpdatePassword(userID uuid.UUID, passwordHash string) error {
	args := m.Called(userID, passwordHash)
	return args.Error(0)
}

func (m *MockUserRepository) VerifyEmail(userID uuid.UUID) error {
	args := m.Called(userID)
	return args.Error(0)
}

func (m *MockUserRepository) Enable2FA(userID uuid.UUID, secret string) error {
	args := m.Called(userID, secret)
	return args.Error(0)
}

func (m *MockUserRepository) Disable2FA(userID uuid.UUID) error {
	args := m.Called(userID)
	return args.Error(0)
}

func (m *MockUserRepository) UpdateLastLogin(userID uuid.UUID) error {
	args := m.Called(userID)
	return args.Error(0)
}

func (m *MockUserRepository) CreateBackupCodes(userID uuid.UUID, codes []string) error {
	args := m.Called(userID, codes)
	return args.Error(0)
}

func (m *MockUserRepository) GetBackupCodes(userID uuid.UUID) ([]domain.BackupCode, error) {
	args := m.Called(userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]domain.BackupCode), args.Error(1)
}

func (m *MockUserRepository) UseBackupCode(userID uuid.UUID, code string) error {
	args := m.Called(userID, code)
	return args.Error(0)
}

func (m *MockUserRepository) CreateOAuthAccount(account *domain.OAuthAccount) error {
	args := m.Called(account)
	return args.Error(0)
}

func (m *MockUserRepository) GetOAuthAccount(provider, providerUserID string) (*domain.OAuthAccount, error) {
	args := m.Called(provider, providerUserID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.OAuthAccount), args.Error(1)
}

func (m *MockUserRepository) GetOAuthAccountsByUserID(userID uuid.UUID) ([]domain.OAuthAccount, error) {
	args := m.Called(userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]domain.OAuthAccount), args.Error(1)
}

func (m *MockUserRepository) DeleteOAuthAccount(userID uuid.UUID, provider string) error {
	args := m.Called(userID, provider)
	return args.Error(0)
}

// MockSessionRepository is a mock implementation of SessionRepository
type MockSessionRepository struct {
	mock.Mock
}

func (m *MockSessionRepository) Create(session *domain.Session) error {
	args := m.Called(session)
	return args.Error(0)
}

func (m *MockSessionRepository) GetByID(id uuid.UUID) (*domain.Session, error) {
	args := m.Called(id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.Session), args.Error(1)
}

func (m *MockSessionRepository) GetByRefreshToken(token string) (*domain.Session, error) {
	args := m.Called(token)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.Session), args.Error(1)
}

func (m *MockSessionRepository) GetActiveSessions(userID uuid.UUID) ([]domain.Session, error) {
	args := m.Called(userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]domain.Session), args.Error(1)
}

func (m *MockSessionRepository) Update(session *domain.Session) error {
	args := m.Called(session)
	return args.Error(0)
}

func (m *MockSessionRepository) Revoke(sessionID uuid.UUID) error {
	args := m.Called(sessionID)
	return args.Error(0)
}

func (m *MockSessionRepository) RevokeAllUserSessions(userID uuid.UUID) error {
	args := m.Called(userID)
	return args.Error(0)
}

func (m *MockSessionRepository) DeleteExpired() error {
	args := m.Called()
	return args.Error(0)
}

func (m *MockSessionRepository) UpdateLastAccessed(sessionID uuid.UUID) error {
	args := m.Called(sessionID)
	return args.Error(0)
}

// MockEmailService is a mock implementation of EmailService
type MockEmailService struct {
	mock.Mock
}

func (m *MockEmailService) SendVerificationEmail(to, token string) error {
	args := m.Called(to, token)
	return args.Error(0)
}

func (m *MockEmailService) SendPasswordResetEmail(to, token string) error {
	args := m.Called(to, token)
	return args.Error(0)
}

func (m *MockEmailService) SendMagicLinkEmail(to, token string) error {
	args := m.Called(to, token)
	return args.Error(0)
}

func (m *MockEmailService) Send2FACode(to, code string) error {
	args := m.Called(to, code)
	return args.Error(0)
}

func (m *MockEmailService) SendPasswordlessEmail(to, token string) error {
	args := m.Called(to, token)
	return args.Error(0)
}

func (m *MockEmailService) SendWelcomeEmail(to, name string) error {
	args := m.Called(to, name)
	return args.Error(0)
}

// MockOTPRepository is a mock implementation of OTPRepository
type MockOTPRepository struct {
	mock.Mock
}

func (m *MockOTPRepository) Create(otp *domain.OTP) error {
	args := m.Called(otp)
	return args.Error(0)
}

func (m *MockOTPRepository) GetByToken(token string) (*domain.OTP, error) {
	args := m.Called(token)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.OTP), args.Error(1)
}

func (m *MockOTPRepository) GetByEmailAndType(email string, otpType domain.OTPType) (*domain.OTP, error) {
	args := m.Called(email, otpType)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.OTP), args.Error(1)
}

func (m *MockOTPRepository) MarkAsUsed(id uuid.UUID) error {
	args := m.Called(id)
	return args.Error(0)
}

func (m *MockOTPRepository) DeleteExpired() error {
	args := m.Called()
	return args.Error(0)
}

func (m *MockOTPRepository) DeleteByUserAndType(userID uuid.UUID, otpType domain.OTPType) error {
	args := m.Called(userID, otpType)
	return args.Error(0)
}

// MockPasswordService is a mock implementation of PasswordService
type MockPasswordService struct {
	mock.Mock
}

func (m *MockPasswordService) HashPassword(password string) (string, error) {
	args := m.Called(password)
	return args.String(0), args.Error(1)
}

func (m *MockPasswordService) VerifyPassword(hash, password string) error {
	args := m.Called(hash, password)
	return args.Error(0)
}

func (m *MockPasswordService) ValidatePasswordStrength(password string) error {
	args := m.Called(password)
	return args.Error(0)
}

// MockJWTService is a mock implementation of JWTService
type MockJWTService struct {
	mock.Mock
}

func (m *MockJWTService) GenerateAccessToken(userID uuid.UUID, email string, claims map[string]string) (string, error) {
	args := m.Called(userID, email, claims)
	return args.String(0), args.Error(1)
}

func (m *MockJWTService) GenerateRefreshToken(userID uuid.UUID, email string) (string, error) {
	args := m.Called(userID, email)
	return args.String(0), args.Error(1)
}

func (m *MockJWTService) ValidateToken(token string, tokenType TokenType) (*Claims, error) {
	args := m.Called(token, tokenType)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*Claims), args.Error(1)
}

func (m *MockJWTService) ParseToken(token string) (*Claims, error) {
	args := m.Called(token)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*Claims), args.Error(1)
}

// MockTOTPService is a mock implementation of TOTPService
type MockTOTPService struct {
	mock.Mock
}

func (m *MockTOTPService) GenerateSecret(email string) (string, string, error) {
	args := m.Called(email)
	return args.String(0), args.String(1), args.Error(2)
}

func (m *MockTOTPService) ValidateCode(secret, code string) bool {
	args := m.Called(secret, code)
	return args.Bool(0)
}

func (m *MockTOTPService) GenerateBackupCodes(count int) ([]string, error) {
	args := m.Called(count)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]string), args.Error(1)
}

// MockPasswordlessService is a mock implementation of PasswordlessService
type MockPasswordlessService struct {
	mock.Mock
}

func (m *MockPasswordlessService) GenerateToken(email string) (*domain.OTP, error) {
	args := m.Called(email)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.OTP), args.Error(1)
}

func (m *MockPasswordlessService) VerifyToken(token string) (*domain.OTP, error) {
	args := m.Called(token)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*domain.OTP), args.Error(1)
}

// MockOAuthService is a mock implementation of OAuthService
type MockOAuthService struct {
	mock.Mock
}

func (m *MockOAuthService) GetAuthURL(provider OAuthProvider, state string) (string, error) {
	args := m.Called(provider, state)
	return args.String(0), args.Error(1)
}

func (m *MockOAuthService) ExchangeCode(provider OAuthProvider, code string) (*oauth2.Token, error) {
	args := m.Called(provider, code)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*oauth2.Token), args.Error(1)
}

func (m *MockOAuthService) GetUserInfo(provider OAuthProvider, token *oauth2.Token) (*OAuthUserInfo, error) {
	args := m.Called(provider, token)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*OAuthUserInfo), args.Error(1)
}

func (m *MockOAuthService) GenerateState() (string, error) {
	args := m.Called()
	return args.String(0), args.Error(1)
}
