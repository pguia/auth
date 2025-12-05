package service

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	authv1 "github.com/guipguia/api/proto/auth/v1"
	"github.com/guipguia/internal/domain"
	"github.com/guipguia/internal/repository"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// AuthService implements the gRPC AuthService interface
type AuthService struct {
	authv1.UnimplementedAuthServiceServer
	userRepo            repository.UserRepository
	sessionRepo         repository.SessionRepository
	otpRepo             repository.OTPRepository
	passwordService     PasswordService
	totpService         TOTPService
	passwordlessService PasswordlessService
	oauthService        OAuthService
	jwtService          JWTService
	emailService        EmailService
}

// NewAuthService creates a new AuthService
func NewAuthService(
	userRepo repository.UserRepository,
	sessionRepo repository.SessionRepository,
	otpRepo repository.OTPRepository,
	passwordService PasswordService,
	totpService TOTPService,
	passwordlessService PasswordlessService,
	oauthService OAuthService,
	jwtService JWTService,
	emailService EmailService,
) *AuthService {
	return &AuthService{
		userRepo:            userRepo,
		sessionRepo:         sessionRepo,
		otpRepo:             otpRepo,
		passwordService:     passwordService,
		totpService:         totpService,
		passwordlessService: passwordlessService,
		oauthService:        oauthService,
		jwtService:          jwtService,
		emailService:        emailService,
	}
}

// Register registers a new user
func (s *AuthService) Register(ctx context.Context, req *authv1.RegisterRequest) (*authv1.RegisterResponse, error) {
	// Validate password strength
	if err := s.passwordService.ValidatePasswordStrength(req.Password); err != nil {
		return nil, fmt.Errorf("password validation failed: %w", err)
	}

	// Check if user already exists
	existingUser, _ := s.userRepo.GetByEmail(req.Email)
	if existingUser != nil {
		return nil, fmt.Errorf("user with email %s already exists", req.Email)
	}

	// Hash password
	passwordHash, err := s.passwordService.HashPassword(req.Password)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	// Create user
	user := &domain.User{
		Email:        req.Email,
		PasswordHash: passwordHash,
		FirstName:    req.FirstName,
		LastName:     req.LastName,
		Metadata:     req.Metadata,
	}

	if err := s.userRepo.Create(user); err != nil {
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	// Generate email verification token
	verificationToken, err := GenerateEmailVerificationToken(user.Email, user.ID, s.otpRepo)
	if err != nil {
		return nil, fmt.Errorf("failed to generate verification token: %w", err)
	}

	// Send verification email
	if err := s.emailService.SendVerificationEmail(user.Email, verificationToken.Token); err != nil {
		// Log error but don't fail registration
		fmt.Printf("Failed to send verification email: %v\n", err)
	}

	return &authv1.RegisterResponse{
		UserId:        user.ID.String(),
		Email:         user.Email,
		EmailVerified: user.EmailVerified,
		Message:       "Registration successful. Please check your email to verify your account.",
	}, nil
}

// Login authenticates a user
func (s *AuthService) Login(ctx context.Context, req *authv1.LoginRequest) (*authv1.LoginResponse, error) {
	// Get user by email
	user, err := s.userRepo.GetByEmail(req.Email)
	if err != nil {
		return nil, fmt.Errorf("invalid credentials")
	}

	// Verify password
	if err := s.passwordService.VerifyPassword(user.PasswordHash, req.Password); err != nil {
		return nil, fmt.Errorf("invalid credentials")
	}

	// Check if 2FA is enabled
	if user.TwoFactorEnabled {
		if req.TotpCode == "" {
			// Create a pending session
			sessionID := uuid.New()
			return &authv1.LoginResponse{
				Requires_2Fa: true,
				SessionId:    sessionID.String(),
			}, nil
		}

		// Verify TOTP code
		if !s.totpService.ValidateCode(user.TwoFactorSecret, req.TotpCode) {
			// Check backup codes
			if err := s.userRepo.UseBackupCode(user.ID, req.TotpCode); err != nil {
				return nil, fmt.Errorf("invalid 2FA code")
			}
		}
	}

	// Generate tokens
	accessToken, err := s.jwtService.GenerateAccessToken(user.ID, user.Email, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to generate access token: %w", err)
	}

	refreshToken, err := s.jwtService.GenerateRefreshToken(user.ID, user.Email)
	if err != nil {
		return nil, fmt.Errorf("failed to generate refresh token: %w", err)
	}

	// Create session
	session := &domain.Session{
		UserID:       user.ID,
		RefreshToken: refreshToken,
		DeviceID:     req.DeviceId,
		DeviceName:   req.DeviceName,
		ExpiresAt:    time.Now().Add(7 * 24 * time.Hour), // 7 days
	}

	if err := s.sessionRepo.Create(session); err != nil {
		return nil, fmt.Errorf("failed to create session: %w", err)
	}

	// Update last login
	if err := s.userRepo.UpdateLastLogin(user.ID); err != nil {
		// Log error but don't fail login
		fmt.Printf("Failed to update last login: %v\n", err)
	}

	return &authv1.LoginResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    int64(15 * 60), // 15 minutes in seconds
		User:         s.userToProto(user),
		SessionId:    session.ID.String(),
	}, nil
}

// RefreshToken refreshes an access token
func (s *AuthService) RefreshToken(ctx context.Context, req *authv1.RefreshTokenRequest) (*authv1.RefreshTokenResponse, error) {
	// Get session by refresh token
	session, err := s.sessionRepo.GetByRefreshToken(req.RefreshToken)
	if err != nil {
		return nil, fmt.Errorf("invalid refresh token")
	}

	// Check if session is active
	if !session.IsActive() {
		return nil, fmt.Errorf("session expired or revoked")
	}

	// Get user
	user, err := s.userRepo.GetByID(session.UserID)
	if err != nil {
		return nil, fmt.Errorf("user not found")
	}

	// Generate new tokens
	accessToken, err := s.jwtService.GenerateAccessToken(user.ID, user.Email, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to generate access token: %w", err)
	}

	newRefreshToken, err := s.jwtService.GenerateRefreshToken(user.ID, user.Email)
	if err != nil {
		return nil, fmt.Errorf("failed to generate refresh token: %w", err)
	}

	// Update session with new refresh token
	session.RefreshToken = newRefreshToken
	session.ExpiresAt = time.Now().Add(7 * 24 * time.Hour)
	if err := s.sessionRepo.Update(session); err != nil {
		return nil, fmt.Errorf("failed to update session: %w", err)
	}

	return &authv1.RefreshTokenResponse{
		AccessToken:  accessToken,
		RefreshToken: newRefreshToken,
		ExpiresIn:    int64(15 * 60), // 15 minutes in seconds
	}, nil
}

// Logout logs out a user
func (s *AuthService) Logout(ctx context.Context, req *authv1.LogoutRequest) (*authv1.LogoutResponse, error) {
	sessionID, err := uuid.Parse(req.SessionId)
	if err != nil {
		return nil, fmt.Errorf("invalid session ID")
	}

	if err := s.sessionRepo.Revoke(sessionID); err != nil {
		return nil, fmt.Errorf("failed to logout: %w", err)
	}

	return &authv1.LogoutResponse{
		Success: true,
		Message: "Logged out successfully",
	}, nil
}

// ChangePassword changes a user's password
func (s *AuthService) ChangePassword(ctx context.Context, req *authv1.ChangePasswordRequest) (*authv1.ChangePasswordResponse, error) {
	userID, err := uuid.Parse(req.UserId)
	if err != nil {
		return nil, fmt.Errorf("invalid user ID")
	}

	// Get user
	user, err := s.userRepo.GetByID(userID)
	if err != nil {
		return nil, fmt.Errorf("user not found")
	}

	// Verify current password
	if err := s.passwordService.VerifyPassword(user.PasswordHash, req.CurrentPassword); err != nil {
		return nil, fmt.Errorf("invalid current password")
	}

	// Validate new password
	if err := s.passwordService.ValidatePasswordStrength(req.NewPassword); err != nil {
		return nil, fmt.Errorf("password validation failed: %w", err)
	}

	// Hash new password
	newPasswordHash, err := s.passwordService.HashPassword(req.NewPassword)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	// Update password
	if err := s.userRepo.UpdatePassword(userID, newPasswordHash); err != nil {
		return nil, fmt.Errorf("failed to update password: %w", err)
	}

	// Revoke all sessions except current one
	if err := s.sessionRepo.RevokeAllUserSessions(userID); err != nil {
		fmt.Printf("Failed to revoke sessions: %v\n", err)
	}

	return &authv1.ChangePasswordResponse{
		Success: true,
		Message: "Password changed successfully",
	}, nil
}

// ForgotPassword initiates password reset
func (s *AuthService) ForgotPassword(ctx context.Context, req *authv1.ForgotPasswordRequest) (*authv1.ForgotPasswordResponse, error) {
	// Get user
	user, err := s.userRepo.GetByEmail(req.Email)
	if err != nil {
		// Don't reveal if user exists or not
		return &authv1.ForgotPasswordResponse{
			Success: true,
			Message: "If an account with that email exists, a password reset link has been sent.",
		}, nil
	}

	// Generate password reset token
	resetToken, err := GeneratePasswordResetToken(user.Email, user.ID, s.otpRepo)
	if err != nil {
		return nil, fmt.Errorf("failed to generate reset token: %w", err)
	}

	// Send password reset email
	if err := s.emailService.SendPasswordResetEmail(user.Email, resetToken.Token); err != nil {
		fmt.Printf("Failed to send password reset email: %v\n", err)
	}

	return &authv1.ForgotPasswordResponse{
		Success: true,
		Message: "If an account with that email exists, a password reset link has been sent.",
	}, nil
}

// ResetPassword resets a user's password
func (s *AuthService) ResetPassword(ctx context.Context, req *authv1.ResetPasswordRequest) (*authv1.ResetPasswordResponse, error) {
	// Verify token
	otp, err := s.otpRepo.GetByToken(req.Token)
	if err != nil {
		return nil, fmt.Errorf("invalid or expired token")
	}

	if otp.Type != domain.OTPTypePasswordReset {
		return nil, fmt.Errorf("invalid token type")
	}

	// Validate new password
	if err := s.passwordService.ValidatePasswordStrength(req.NewPassword); err != nil {
		return nil, fmt.Errorf("password validation failed: %w", err)
	}

	// Hash new password
	newPasswordHash, err := s.passwordService.HashPassword(req.NewPassword)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	// Update password
	if err := s.userRepo.UpdatePassword(otp.UserID, newPasswordHash); err != nil {
		return nil, fmt.Errorf("failed to update password: %w", err)
	}

	// Mark token as used
	if err := s.otpRepo.MarkAsUsed(otp.ID); err != nil {
		fmt.Printf("Failed to mark token as used: %v\n", err)
	}

	// Revoke all sessions
	if err := s.sessionRepo.RevokeAllUserSessions(otp.UserID); err != nil {
		fmt.Printf("Failed to revoke sessions: %v\n", err)
	}

	return &authv1.ResetPasswordResponse{
		Success: true,
		Message: "Password reset successfully",
	}, nil
}

// Enable2FA enables 2FA for a user
func (s *AuthService) Enable2FA(ctx context.Context, req *authv1.Enable2FARequest) (*authv1.Enable2FAResponse, error) {
	userID, err := uuid.Parse(req.UserId)
	if err != nil {
		return nil, fmt.Errorf("invalid user ID")
	}

	// Get user
	user, err := s.userRepo.GetByID(userID)
	if err != nil {
		return nil, fmt.Errorf("user not found")
	}

	// Generate TOTP secret
	secret, qrCodeURL, err := s.totpService.GenerateSecret(user.Email)
	if err != nil {
		return nil, fmt.Errorf("failed to generate 2FA secret: %w", err)
	}

	// Generate backup codes
	backupCodes, err := s.totpService.GenerateBackupCodes(10)
	if err != nil {
		return nil, fmt.Errorf("failed to generate backup codes: %w", err)
	}

	// Store backup codes
	if err := s.userRepo.CreateBackupCodes(userID, backupCodes); err != nil {
		return nil, fmt.Errorf("failed to store backup codes: %w", err)
	}

	// Enable 2FA (secret will be stored after verification)
	if err := s.userRepo.Enable2FA(userID, secret); err != nil {
		return nil, fmt.Errorf("failed to enable 2FA: %w", err)
	}

	return &authv1.Enable2FAResponse{
		Secret:      secret,
		QrCodeUrl:   qrCodeURL,
		BackupCodes: backupCodes,
	}, nil
}

// Verify2FA verifies a 2FA code
func (s *AuthService) Verify2FA(ctx context.Context, req *authv1.Verify2FARequest) (*authv1.Verify2FAResponse, error) {
	userID, err := uuid.Parse(req.UserId)
	if err != nil {
		return nil, fmt.Errorf("invalid user ID")
	}

	// Get user
	user, err := s.userRepo.GetByID(userID)
	if err != nil {
		return nil, fmt.Errorf("user not found")
	}

	// Verify TOTP code
	if !s.totpService.ValidateCode(user.TwoFactorSecret, req.TotpCode) {
		return nil, fmt.Errorf("invalid 2FA code")
	}

	// If this is completing a login flow, generate tokens
	if req.SessionId != "" {
		accessToken, err := s.jwtService.GenerateAccessToken(user.ID, user.Email, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to generate access token: %w", err)
		}

		refreshToken, err := s.jwtService.GenerateRefreshToken(user.ID, user.Email)
		if err != nil {
			return nil, fmt.Errorf("failed to generate refresh token: %w", err)
		}

		return &authv1.Verify2FAResponse{
			Verified:     true,
			AccessToken:  accessToken,
			RefreshToken: refreshToken,
			ExpiresIn:    int64(15 * 60),
			Message:      "2FA verified successfully",
		}, nil
	}

	return &authv1.Verify2FAResponse{
		Verified: true,
		Message:  "2FA verified successfully",
	}, nil
}

// Disable2FA disables 2FA for a user
func (s *AuthService) Disable2FA(ctx context.Context, req *authv1.Disable2FARequest) (*authv1.Disable2FAResponse, error) {
	userID, err := uuid.Parse(req.UserId)
	if err != nil {
		return nil, fmt.Errorf("invalid user ID")
	}

	// Get user
	user, err := s.userRepo.GetByID(userID)
	if err != nil {
		return nil, fmt.Errorf("user not found")
	}

	// Verify password
	if err := s.passwordService.VerifyPassword(user.PasswordHash, req.Password); err != nil {
		return nil, fmt.Errorf("invalid password")
	}

	// Verify TOTP code
	if !s.totpService.ValidateCode(user.TwoFactorSecret, req.TotpCode) {
		return nil, fmt.Errorf("invalid 2FA code")
	}

	// Disable 2FA
	if err := s.userRepo.Disable2FA(userID); err != nil {
		return nil, fmt.Errorf("failed to disable 2FA: %w", err)
	}

	return &authv1.Disable2FAResponse{
		Success: true,
		Message: "2FA disabled successfully",
	}, nil
}

// Generate2FABackupCodes generates new backup codes
func (s *AuthService) Generate2FABackupCodes(ctx context.Context, req *authv1.Generate2FABackupCodesRequest) (*authv1.Generate2FABackupCodesResponse, error) {
	userID, err := uuid.Parse(req.UserId)
	if err != nil {
		return nil, fmt.Errorf("invalid user ID")
	}

	// Get user
	user, err := s.userRepo.GetByID(userID)
	if err != nil {
		return nil, fmt.Errorf("user not found")
	}

	// Verify password
	if err := s.passwordService.VerifyPassword(user.PasswordHash, req.Password); err != nil {
		return nil, fmt.Errorf("invalid password")
	}

	// Generate new backup codes
	backupCodes, err := s.totpService.GenerateBackupCodes(10)
	if err != nil {
		return nil, fmt.Errorf("failed to generate backup codes: %w", err)
	}

	// Store backup codes
	if err := s.userRepo.CreateBackupCodes(userID, backupCodes); err != nil {
		return nil, fmt.Errorf("failed to store backup codes: %w", err)
	}

	return &authv1.Generate2FABackupCodesResponse{
		BackupCodes: backupCodes,
	}, nil
}

// SendPasswordlessEmail sends a passwordless login email
func (s *AuthService) SendPasswordlessEmail(ctx context.Context, req *authv1.SendPasswordlessEmailRequest) (*authv1.SendPasswordlessEmailResponse, error) {
	// Generate passwordless token
	token, err := s.passwordlessService.GenerateToken(req.Email)
	if err != nil {
		return nil, fmt.Errorf("failed to generate passwordless token: %w", err)
	}

	// Send passwordless email
	if err := s.emailService.SendPasswordlessEmail(req.Email, token.Token); err != nil {
		return nil, fmt.Errorf("failed to send passwordless email: %w", err)
	}

	return &authv1.SendPasswordlessEmailResponse{
		Success:   true,
		Message:   "Passwordless login link sent to your email",
		ExpiresIn: int64(15 * 60), // 15 minutes
	}, nil
}

// VerifyPasswordlessToken verifies a passwordless login token
func (s *AuthService) VerifyPasswordlessToken(ctx context.Context, req *authv1.VerifyPasswordlessTokenRequest) (*authv1.VerifyPasswordlessTokenResponse, error) {
	// Verify token
	otp, err := s.passwordlessService.VerifyToken(req.Token)
	if err != nil {
		return nil, fmt.Errorf("invalid or expired token: %w", err)
	}

	// Get or create user
	user, err := s.userRepo.GetByEmail(otp.Email)
	if err != nil {
		// Create new user
		user = &domain.User{
			Email:         otp.Email,
			EmailVerified: true,
		}
		if err := s.userRepo.Create(user); err != nil {
			return nil, fmt.Errorf("failed to create user: %w", err)
		}
	}

	// Generate tokens
	accessToken, err := s.jwtService.GenerateAccessToken(user.ID, user.Email, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to generate access token: %w", err)
	}

	refreshToken, err := s.jwtService.GenerateRefreshToken(user.ID, user.Email)
	if err != nil {
		return nil, fmt.Errorf("failed to generate refresh token: %w", err)
	}

	// Create session
	session := &domain.Session{
		UserID:       user.ID,
		RefreshToken: refreshToken,
		DeviceID:     req.DeviceId,
		DeviceName:   req.DeviceName,
		ExpiresAt:    time.Now().Add(7 * 24 * time.Hour),
	}

	if err := s.sessionRepo.Create(session); err != nil {
		return nil, fmt.Errorf("failed to create session: %w", err)
	}

	// Update last login
	if err := s.userRepo.UpdateLastLogin(user.ID); err != nil {
		fmt.Printf("Failed to update last login: %v\n", err)
	}

	return &authv1.VerifyPasswordlessTokenResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    int64(15 * 60),
		User:         s.userToProto(user),
		SessionId:    session.ID.String(),
	}, nil
}

// Helper function to convert domain.User to proto User
func (s *AuthService) userToProto(user *domain.User) *authv1.User {
	protoUser := &authv1.User{
		Id:               user.ID.String(),
		Email:            user.Email,
		EmailVerified:    user.EmailVerified,
		FirstName:        user.FirstName,
		LastName:         user.LastName,
		PhoneNumber:      user.PhoneNumber,
		TwoFactorEnabled: user.TwoFactorEnabled,
		CreatedAt:        timestamppb.New(user.CreatedAt),
		UpdatedAt:        timestamppb.New(user.UpdatedAt),
		Metadata:         user.Metadata,
	}

	if user.LastLoginAt != nil {
		protoUser.LastLoginAt = timestamppb.New(*user.LastLoginAt)
	}

	// Convert OAuth accounts
	for _, oauth := range user.OAuthAccounts {
		protoOAuth := &authv1.OAuthAccount{
			Provider:       s.oauthProviderToProto(oauth.Provider),
			ProviderUserId: oauth.ProviderUserID,
			Email:          oauth.Email,
			LinkedAt:       timestamppb.New(oauth.LinkedAt),
		}
		protoUser.OauthAccounts = append(protoUser.OauthAccounts, protoOAuth)
	}

	return protoUser
}

// Helper function to convert OAuth provider string to proto enum
func (s *AuthService) oauthProviderToProto(provider string) authv1.OAuthProvider {
	switch provider {
	case "google":
		return authv1.OAuthProvider_OAUTH_PROVIDER_GOOGLE
	case "github":
		return authv1.OAuthProvider_OAUTH_PROVIDER_GITHUB
	case "facebook":
		return authv1.OAuthProvider_OAUTH_PROVIDER_FACEBOOK
	case "apple":
		return authv1.OAuthProvider_OAUTH_PROVIDER_APPLE
	case "microsoft":
		return authv1.OAuthProvider_OAUTH_PROVIDER_MICROSOFT
	case "discord":
		return authv1.OAuthProvider_OAUTH_PROVIDER_DISCORD
	default:
		return authv1.OAuthProvider_OAUTH_PROVIDER_UNSPECIFIED
	}
}
