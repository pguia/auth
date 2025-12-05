package repository

import (
	"testing"

	"github.com/google/uuid"
	"github.com/guipguia/internal/domain"
	"github.com/stretchr/testify/assert"
)

// Test: NewUserRepository
func TestNewUserRepository(t *testing.T) {
	db := setupTestDB(t)
	repo := NewUserRepository(db)

	assert.NotNil(t, repo)
}

// Test: Create User
func TestUserRepository_Create(t *testing.T) {
	db := setupTestDB(t)
	repo := NewUserRepository(db)

	user := &domain.User{
		Email:        "test@example.com",
		PasswordHash: "hashed-password",
		FirstName:    "John",
		LastName:     "Doe",
	}

	err := repo.Create(user)

	assert.NoError(t, err)
	assert.NotEqual(t, uuid.Nil, user.ID)
}

// Test: GetByID Success
func TestUserRepository_GetByID_Success(t *testing.T) {
	db := setupTestDB(t)
	repo := NewUserRepository(db)

	user := &domain.User{
		Email:        "test@example.com",
		PasswordHash: "hashed-password",
	}
	err := repo.Create(user)
	assert.NoError(t, err)

	retrieved, err := repo.GetByID(user.ID)

	assert.NoError(t, err)
	assert.NotNil(t, retrieved)
	assert.Equal(t, user.Email, retrieved.Email)
}

// Test: GetByID Not Found
func TestUserRepository_GetByID_NotFound(t *testing.T) {
	db := setupTestDB(t)
	repo := NewUserRepository(db)

	retrieved, err := repo.GetByID(uuid.New())

	assert.Error(t, err)
	assert.Nil(t, retrieved)
	assert.Contains(t, err.Error(), "user not found")
}

// Test: GetByEmail Success
func TestUserRepository_GetByEmail_Success(t *testing.T) {
	db := setupTestDB(t)
	repo := NewUserRepository(db)

	user := &domain.User{
		Email:        "test@example.com",
		PasswordHash: "hashed-password",
	}
	err := repo.Create(user)
	assert.NoError(t, err)

	retrieved, err := repo.GetByEmail("test@example.com")

	assert.NoError(t, err)
	assert.NotNil(t, retrieved)
	assert.Equal(t, user.ID, retrieved.ID)
}

// Test: GetByEmail Not Found
func TestUserRepository_GetByEmail_NotFound(t *testing.T) {
	db := setupTestDB(t)
	repo := NewUserRepository(db)

	retrieved, err := repo.GetByEmail("nonexistent@example.com")

	assert.Error(t, err)
	assert.Nil(t, retrieved)
	assert.Contains(t, err.Error(), "user not found")
}

// Test: Update User
func TestUserRepository_Update(t *testing.T) {
	db := setupTestDB(t)
	repo := NewUserRepository(db)

	user := &domain.User{
		Email:        "test@example.com",
		PasswordHash: "hashed-password",
		FirstName:    "John",
	}
	err := repo.Create(user)
	assert.NoError(t, err)

	user.FirstName = "Jane"
	err = repo.Update(user)

	assert.NoError(t, err)

	retrieved, _ := repo.GetByID(user.ID)
	assert.Equal(t, "Jane", retrieved.FirstName)
}

// Test: Delete User
func TestUserRepository_Delete(t *testing.T) {
	db := setupTestDB(t)
	repo := NewUserRepository(db)

	user := &domain.User{
		Email:        "test@example.com",
		PasswordHash: "hashed-password",
	}
	err := repo.Create(user)
	assert.NoError(t, err)

	err = repo.Delete(user.ID)

	assert.NoError(t, err)

	retrieved, err := repo.GetByID(user.ID)
	assert.Error(t, err)
	assert.Nil(t, retrieved)
}

// Test: UpdatePassword
func TestUserRepository_UpdatePassword(t *testing.T) {
	db := setupTestDB(t)
	repo := NewUserRepository(db)

	user := &domain.User{
		Email:        "test@example.com",
		PasswordHash: "old-hash",
	}
	err := repo.Create(user)
	assert.NoError(t, err)

	err = repo.UpdatePassword(user.ID, "new-hash")

	assert.NoError(t, err)

	retrieved, _ := repo.GetByID(user.ID)
	assert.Equal(t, "new-hash", retrieved.PasswordHash)
}

// Test: VerifyEmail
func TestUserRepository_VerifyEmail(t *testing.T) {
	db := setupTestDB(t)
	repo := NewUserRepository(db)

	user := &domain.User{
		Email:         "test@example.com",
		PasswordHash:  "hash",
		EmailVerified: false,
	}
	err := repo.Create(user)
	assert.NoError(t, err)

	err = repo.VerifyEmail(user.ID)

	assert.NoError(t, err)

	retrieved, _ := repo.GetByID(user.ID)
	assert.True(t, retrieved.EmailVerified)
}

// Test: Enable2FA
func TestUserRepository_Enable2FA(t *testing.T) {
	db := setupTestDB(t)
	repo := NewUserRepository(db)

	user := &domain.User{
		Email:        "test@example.com",
		PasswordHash: "hash",
	}
	err := repo.Create(user)
	assert.NoError(t, err)

	err = repo.Enable2FA(user.ID, "secret123")

	assert.NoError(t, err)

	retrieved, _ := repo.GetByID(user.ID)
	assert.True(t, retrieved.TwoFactorEnabled)
	assert.Equal(t, "secret123", retrieved.TwoFactorSecret)
}

// Test: Disable2FA
func TestUserRepository_Disable2FA(t *testing.T) {
	db := setupTestDB(t)
	repo := NewUserRepository(db)

	user := &domain.User{
		Email:            "test@example.com",
		PasswordHash:     "hash",
		TwoFactorEnabled: true,
		TwoFactorSecret:  "secret123",
	}
	err := repo.Create(user)
	assert.NoError(t, err)

	err = repo.Disable2FA(user.ID)

	assert.NoError(t, err)

	retrieved, _ := repo.GetByID(user.ID)
	assert.False(t, retrieved.TwoFactorEnabled)
	assert.Empty(t, retrieved.TwoFactorSecret)
}

// Test: UpdateLastLogin
func TestUserRepository_UpdateLastLogin(t *testing.T) {
	db := setupTestDB(t)
	repo := NewUserRepository(db)

	user := &domain.User{
		Email:        "test@example.com",
		PasswordHash: "hash",
	}
	err := repo.Create(user)
	assert.NoError(t, err)

	err = repo.UpdateLastLogin(user.ID)

	assert.NoError(t, err)

	retrieved, _ := repo.GetByID(user.ID)
	assert.NotNil(t, retrieved.LastLoginAt)
}

// Test: CreateBackupCodes
func TestUserRepository_CreateBackupCodes(t *testing.T) {
	db := setupTestDB(t)
	repo := NewUserRepository(db)

	user := &domain.User{
		Email:        "test@example.com",
		PasswordHash: "hash",
	}
	err := repo.Create(user)
	assert.NoError(t, err)

	codes := []string{"CODE1-1234", "CODE2-5678"}
	err = repo.CreateBackupCodes(user.ID, codes)

	assert.NoError(t, err)

	backupCodes, err := repo.GetBackupCodes(user.ID)
	assert.NoError(t, err)
	assert.Len(t, backupCodes, 2)
}

// Test: GetBackupCodes
func TestUserRepository_GetBackupCodes(t *testing.T) {
	db := setupTestDB(t)
	repo := NewUserRepository(db)

	user := &domain.User{
		Email:        "test@example.com",
		PasswordHash: "hash",
	}
	err := repo.Create(user)
	assert.NoError(t, err)

	codes := []string{"CODE1-1234", "CODE2-5678", "CODE3-9012"}
	err = repo.CreateBackupCodes(user.ID, codes)
	assert.NoError(t, err)

	backupCodes, err := repo.GetBackupCodes(user.ID)

	assert.NoError(t, err)
	assert.Len(t, backupCodes, 3)
}

// Test: UseBackupCode Success
func TestUserRepository_UseBackupCode_Success(t *testing.T) {
	db := setupTestDB(t)
	repo := NewUserRepository(db)

	user := &domain.User{
		Email:        "test@example.com",
		PasswordHash: "hash",
	}
	err := repo.Create(user)
	assert.NoError(t, err)

	codes := []string{"CODE1-1234", "CODE2-5678"}
	err = repo.CreateBackupCodes(user.ID, codes)
	assert.NoError(t, err)

	err = repo.UseBackupCode(user.ID, "CODE1-1234")

	assert.NoError(t, err)

	// GetBackupCodes only returns unused codes
	backupCodes, _ := repo.GetBackupCodes(user.ID)
	assert.Len(t, backupCodes, 1)
	assert.Equal(t, "CODE2-5678", backupCodes[0].Code)
}

// Test: UseBackupCode Invalid
func TestUserRepository_UseBackupCode_Invalid(t *testing.T) {
	db := setupTestDB(t)
	repo := NewUserRepository(db)

	user := &domain.User{
		Email:        "test@example.com",
		PasswordHash: "hash",
	}
	err := repo.Create(user)
	assert.NoError(t, err)

	err = repo.UseBackupCode(user.ID, "INVALID-CODE")

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "backup code not found or already used")
}

// Test: CreateOAuthAccount
func TestUserRepository_CreateOAuthAccount(t *testing.T) {
	db := setupTestDB(t)
	repo := NewUserRepository(db)

	user := &domain.User{
		Email:        "test@example.com",
		PasswordHash: "hash",
	}
	err := repo.Create(user)
	assert.NoError(t, err)

	oauthAccount := &domain.OAuthAccount{
		UserID:         user.ID,
		Provider:       "google",
		ProviderUserID: "google-123",
		Email:          "test@example.com",
		AccessToken:    "access-token",
	}

	err = repo.CreateOAuthAccount(oauthAccount)

	assert.NoError(t, err)
	assert.NotEqual(t, uuid.Nil, oauthAccount.ID)
}

// Test: GetOAuthAccount Success
func TestUserRepository_GetOAuthAccount_Success(t *testing.T) {
	db := setupTestDB(t)
	repo := NewUserRepository(db)

	user := &domain.User{
		Email:        "test@example.com",
		PasswordHash: "hash",
	}
	err := repo.Create(user)
	assert.NoError(t, err)

	oauthAccount := &domain.OAuthAccount{
		UserID:         user.ID,
		Provider:       "google",
		ProviderUserID: "google-123",
		Email:          "test@example.com",
	}
	err = repo.CreateOAuthAccount(oauthAccount)
	assert.NoError(t, err)

	retrieved, err := repo.GetOAuthAccount("google", "google-123")

	assert.NoError(t, err)
	assert.NotNil(t, retrieved)
	assert.Equal(t, user.ID, retrieved.UserID)
}

// Test: GetOAuthAccount Not Found
func TestUserRepository_GetOAuthAccount_NotFound(t *testing.T) {
	db := setupTestDB(t)
	repo := NewUserRepository(db)

	retrieved, err := repo.GetOAuthAccount("google", "nonexistent")

	assert.Error(t, err)
	assert.Nil(t, retrieved)
}

// Test: GetOAuthAccountsByUserID
func TestUserRepository_GetOAuthAccountsByUserID(t *testing.T) {
	db := setupTestDB(t)
	repo := NewUserRepository(db)

	user := &domain.User{
		Email:        "test@example.com",
		PasswordHash: "hash",
	}
	err := repo.Create(user)
	assert.NoError(t, err)

	oauth1 := &domain.OAuthAccount{
		UserID:         user.ID,
		Provider:       "google",
		ProviderUserID: "google-123",
	}
	oauth2 := &domain.OAuthAccount{
		UserID:         user.ID,
		Provider:       "github",
		ProviderUserID: "github-456",
	}
	repo.CreateOAuthAccount(oauth1)
	repo.CreateOAuthAccount(oauth2)

	accounts, err := repo.GetOAuthAccountsByUserID(user.ID)

	assert.NoError(t, err)
	assert.Len(t, accounts, 2)
}

// Test: DeleteOAuthAccount
func TestUserRepository_DeleteOAuthAccount(t *testing.T) {
	db := setupTestDB(t)
	repo := NewUserRepository(db)

	user := &domain.User{
		Email:        "test@example.com",
		PasswordHash: "hash",
	}
	err := repo.Create(user)
	assert.NoError(t, err)

	oauthAccount := &domain.OAuthAccount{
		UserID:         user.ID,
		Provider:       "google",
		ProviderUserID: "google-123",
	}
	err = repo.CreateOAuthAccount(oauthAccount)
	assert.NoError(t, err)

	err = repo.DeleteOAuthAccount(user.ID, "google")

	assert.NoError(t, err)

	retrieved, err := repo.GetOAuthAccount("google", "google-123")
	assert.Error(t, err)
	assert.Nil(t, retrieved)
}
