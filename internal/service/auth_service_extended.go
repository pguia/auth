package service

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	authv1 "github.com/guipguia/api/proto/auth/v1"
	"github.com/guipguia/internal/domain"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// GetOAuthURL generates an OAuth authorization URL
func (s *AuthService) GetOAuthURL(ctx context.Context, req *authv1.GetOAuthURLRequest) (*authv1.GetOAuthURLResponse, error) {
	provider := s.protoToOAuthProvider(req.Provider)

	// Generate state for CSRF protection
	state, err := s.oauthService.GenerateState()
	if err != nil {
		return nil, fmt.Errorf("failed to generate state: %w", err)
	}

	// Get OAuth URL
	authURL, err := s.oauthService.GetAuthURL(provider, state)
	if err != nil {
		return nil, fmt.Errorf("failed to generate OAuth URL: %w", err)
	}

	return &authv1.GetOAuthURLResponse{
		AuthUrl: authURL,
		State:   state,
	}, nil
}

// OAuthCallback handles OAuth callback
func (s *AuthService) OAuthCallback(ctx context.Context, req *authv1.OAuthCallbackRequest) (*authv1.OAuthCallbackResponse, error) {
	provider := s.protoToOAuthProvider(req.Provider)

	// Exchange code for token
	token, err := s.oauthService.ExchangeCode(provider, req.Code)
	if err != nil {
		return nil, fmt.Errorf("failed to exchange code: %w", err)
	}

	// Get user info from provider
	userInfo, err := s.oauthService.GetUserInfo(provider, token)
	if err != nil {
		return nil, fmt.Errorf("failed to get user info: %w", err)
	}

	// Check if OAuth account already exists
	oauthAccount, err := s.userRepo.GetOAuthAccount(string(provider), userInfo.ProviderUserID)

	var user *domain.User
	isNewUser := false

	if err != nil {
		// OAuth account doesn't exist, check if user exists by email
		user, err = s.userRepo.GetByEmail(userInfo.Email)
		if err != nil {
			// Create new user
			user = &domain.User{
				Email:         userInfo.Email,
				FirstName:     userInfo.FirstName,
				LastName:      userInfo.LastName,
				EmailVerified: true, // OAuth email is already verified
			}

			if err := s.userRepo.Create(user); err != nil {
				return nil, fmt.Errorf("failed to create user: %w", err)
			}

			isNewUser = true
		}

		// Create OAuth account link
		oauthAccount = &domain.OAuthAccount{
			UserID:         user.ID,
			Provider:       string(provider),
			ProviderUserID: userInfo.ProviderUserID,
			Email:          userInfo.Email,
			AccessToken:    token.AccessToken,
			RefreshToken:   token.RefreshToken,
		}

		if !token.Expiry.IsZero() {
			oauthAccount.ExpiresAt = &token.Expiry
		}

		if err := s.userRepo.CreateOAuthAccount(oauthAccount); err != nil {
			return nil, fmt.Errorf("failed to create OAuth account: %w", err)
		}
	} else {
		// OAuth account exists, get the user
		user, err = s.userRepo.GetByID(oauthAccount.UserID)
		if err != nil {
			return nil, fmt.Errorf("user not found")
		}
	}

	// Generate JWT tokens
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

	return &authv1.OAuthCallbackResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    int64(15 * 60),
		User:         s.userToProto(user),
		IsNewUser:    isNewUser,
		SessionId:    session.ID.String(),
	}, nil
}

// LinkOAuthAccount links an OAuth account to an existing user
func (s *AuthService) LinkOAuthAccount(ctx context.Context, req *authv1.LinkOAuthAccountRequest) (*authv1.LinkOAuthAccountResponse, error) {
	userID, err := uuid.Parse(req.UserId)
	if err != nil {
		return nil, fmt.Errorf("invalid user ID")
	}

	provider := s.protoToOAuthProvider(req.Provider)

	// Exchange code for token
	token, err := s.oauthService.ExchangeCode(provider, req.Code)
	if err != nil {
		return nil, fmt.Errorf("failed to exchange code: %w", err)
	}

	// Get user info from provider
	userInfo, err := s.oauthService.GetUserInfo(provider, token)
	if err != nil {
		return nil, fmt.Errorf("failed to get user info: %w", err)
	}

	// Create OAuth account link
	oauthAccount := &domain.OAuthAccount{
		UserID:         userID,
		Provider:       string(provider),
		ProviderUserID: userInfo.ProviderUserID,
		Email:          userInfo.Email,
		AccessToken:    token.AccessToken,
		RefreshToken:   token.RefreshToken,
	}

	if !token.Expiry.IsZero() {
		oauthAccount.ExpiresAt = &token.Expiry
	}

	if err := s.userRepo.CreateOAuthAccount(oauthAccount); err != nil {
		return nil, fmt.Errorf("failed to link OAuth account: %w", err)
	}

	return &authv1.LinkOAuthAccountResponse{
		Success: true,
		Message: "OAuth account linked successfully",
		OauthAccount: &authv1.OAuthAccount{
			Provider:       req.Provider,
			ProviderUserId: userInfo.ProviderUserID,
			Email:          userInfo.Email,
			LinkedAt:       timestamppb.Now(),
		},
	}, nil
}

// UnlinkOAuthAccount unlinks an OAuth account from a user
func (s *AuthService) UnlinkOAuthAccount(ctx context.Context, req *authv1.UnlinkOAuthAccountRequest) (*authv1.UnlinkOAuthAccountResponse, error) {
	userID, err := uuid.Parse(req.UserId)
	if err != nil {
		return nil, fmt.Errorf("invalid user ID")
	}

	provider := s.protoToOAuthProvider(req.Provider)

	if err := s.userRepo.DeleteOAuthAccount(userID, string(provider)); err != nil {
		return nil, fmt.Errorf("failed to unlink OAuth account: %w", err)
	}

	return &authv1.UnlinkOAuthAccountResponse{
		Success: true,
		Message: "OAuth account unlinked successfully",
	}, nil
}

// ValidateToken validates an access token
func (s *AuthService) ValidateToken(ctx context.Context, req *authv1.ValidateTokenRequest) (*authv1.ValidateTokenResponse, error) {
	claims, err := s.jwtService.ValidateToken(req.AccessToken, AccessToken)
	if err != nil {
		return &authv1.ValidateTokenResponse{
			Valid: false,
		}, nil
	}

	// Convert extra claims to map
	claimsMap := make(map[string]string)
	for k, v := range claims.Extra {
		claimsMap[k] = v
	}

	return &authv1.ValidateTokenResponse{
		Valid:     true,
		UserId:    claims.UserID,
		Email:     claims.Email,
		Claims:    claimsMap,
		ExpiresAt: timestamppb.New(claims.ExpiresAt.Time),
	}, nil
}

// RevokeToken revokes a token
func (s *AuthService) RevokeToken(ctx context.Context, req *authv1.RevokeTokenRequest) (*authv1.RevokeTokenResponse, error) {
	// For refresh tokens, revoke the session
	if req.TokenType == authv1.TokenType_TOKEN_TYPE_REFRESH {
		session, err := s.sessionRepo.GetByRefreshToken(req.Token)
		if err != nil {
			return nil, fmt.Errorf("session not found")
		}

		if err := s.sessionRepo.Revoke(session.ID); err != nil {
			return nil, fmt.Errorf("failed to revoke session: %w", err)
		}

		return &authv1.RevokeTokenResponse{
			Success: true,
			Message: "Token revoked successfully",
		}, nil
	}

	// For access tokens, we can't revoke them (they're stateless JWT)
	// In a production system, you might want to maintain a blacklist
	return &authv1.RevokeTokenResponse{
		Success: true,
		Message: "Access tokens cannot be revoked (they expire naturally)",
	}, nil
}

// GetActiveSessions retrieves all active sessions for a user
func (s *AuthService) GetActiveSessions(ctx context.Context, req *authv1.GetActiveSessionsRequest) (*authv1.GetActiveSessionsResponse, error) {
	userID, err := uuid.Parse(req.UserId)
	if err != nil {
		return nil, fmt.Errorf("invalid user ID")
	}

	sessions, err := s.sessionRepo.GetActiveSessions(userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get sessions: %w", err)
	}

	protoSessions := make([]*authv1.Session, len(sessions))
	for i, session := range sessions {
		protoSessions[i] = &authv1.Session{
			Id:             session.ID.String(),
			UserId:         session.UserID.String(),
			DeviceId:       session.DeviceID,
			DeviceName:     session.DeviceName,
			IpAddress:      session.IPAddress,
			UserAgent:      session.UserAgent,
			CreatedAt:      timestamppb.New(session.CreatedAt),
			LastAccessedAt: timestamppb.New(session.LastAccessedAt),
			ExpiresAt:      timestamppb.New(session.ExpiresAt),
		}
	}

	return &authv1.GetActiveSessionsResponse{
		Sessions: protoSessions,
	}, nil
}

// RevokeSession revokes a specific session
func (s *AuthService) RevokeSession(ctx context.Context, req *authv1.RevokeSessionRequest) (*authv1.RevokeSessionResponse, error) {
	sessionID, err := uuid.Parse(req.SessionId)
	if err != nil {
		return nil, fmt.Errorf("invalid session ID")
	}

	// Verify session belongs to user
	session, err := s.sessionRepo.GetByID(sessionID)
	if err != nil {
		return nil, fmt.Errorf("session not found")
	}

	if session.UserID.String() != req.UserId {
		return nil, fmt.Errorf("unauthorized")
	}

	if err := s.sessionRepo.Revoke(sessionID); err != nil {
		return nil, fmt.Errorf("failed to revoke session: %w", err)
	}

	return &authv1.RevokeSessionResponse{
		Success: true,
		Message: "Session revoked successfully",
	}, nil
}

// GetUserProfile retrieves a user's profile
func (s *AuthService) GetUserProfile(ctx context.Context, req *authv1.GetUserProfileRequest) (*authv1.GetUserProfileResponse, error) {
	userID, err := uuid.Parse(req.UserId)
	if err != nil {
		return nil, fmt.Errorf("invalid user ID")
	}

	user, err := s.userRepo.GetByID(userID)
	if err != nil {
		return nil, fmt.Errorf("user not found")
	}

	return &authv1.GetUserProfileResponse{
		User: s.userToProto(user),
	}, nil
}

// UpdateUserProfile updates a user's profile
func (s *AuthService) UpdateUserProfile(ctx context.Context, req *authv1.UpdateUserProfileRequest) (*authv1.UpdateUserProfileResponse, error) {
	userID, err := uuid.Parse(req.UserId)
	if err != nil {
		return nil, fmt.Errorf("invalid user ID")
	}

	user, err := s.userRepo.GetByID(userID)
	if err != nil {
		return nil, fmt.Errorf("user not found")
	}

	// Update fields
	if req.FirstName != "" {
		user.FirstName = req.FirstName
	}
	if req.LastName != "" {
		user.LastName = req.LastName
	}
	if req.PhoneNumber != "" {
		user.PhoneNumber = req.PhoneNumber
	}
	if req.Metadata != nil {
		user.Metadata = req.Metadata
	}

	if err := s.userRepo.Update(user); err != nil {
		return nil, fmt.Errorf("failed to update user: %w", err)
	}

	return &authv1.UpdateUserProfileResponse{
		User: s.userToProto(user),
	}, nil
}

// VerifyEmail verifies a user's email
func (s *AuthService) VerifyEmail(ctx context.Context, req *authv1.VerifyEmailRequest) (*authv1.VerifyEmailResponse, error) {
	// Get OTP by token
	otp, err := s.otpRepo.GetByToken(req.Token)
	if err != nil {
		return nil, fmt.Errorf("invalid or expired token")
	}

	if otp.Type != domain.OTPTypeEmailVerification {
		return nil, fmt.Errorf("invalid token type")
	}

	// Verify email
	if err := s.userRepo.VerifyEmail(otp.UserID); err != nil {
		return nil, fmt.Errorf("failed to verify email: %w", err)
	}

	// Mark token as used
	if err := s.otpRepo.MarkAsUsed(otp.ID); err != nil {
		fmt.Printf("Failed to mark token as used: %v\n", err)
	}

	return &authv1.VerifyEmailResponse{
		Success: true,
		Message: "Email verified successfully",
	}, nil
}

// ResendVerificationEmail resends the verification email
func (s *AuthService) ResendVerificationEmail(ctx context.Context, req *authv1.ResendVerificationEmailRequest) (*authv1.ResendVerificationEmailResponse, error) {
	// Get user
	user, err := s.userRepo.GetByEmail(req.Email)
	if err != nil {
		// Don't reveal if user exists
		return &authv1.ResendVerificationEmailResponse{
			Success: true,
			Message: "If an unverified account exists, a verification email has been sent.",
		}, nil
	}

	// Check if already verified
	if user.EmailVerified {
		return &authv1.ResendVerificationEmailResponse{
			Success: true,
			Message: "Email is already verified.",
		}, nil
	}

	// Generate new verification token
	verificationToken, err := GenerateEmailVerificationToken(user.Email, user.ID, s.otpRepo)
	if err != nil {
		return nil, fmt.Errorf("failed to generate verification token: %w", err)
	}

	// Send verification email
	if err := s.emailService.SendVerificationEmail(user.Email, verificationToken.Token); err != nil {
		fmt.Printf("Failed to send verification email: %v\n", err)
	}

	return &authv1.ResendVerificationEmailResponse{
		Success: true,
		Message: "Verification email sent.",
	}, nil
}

// Helper function to convert proto OAuth provider to service OAuth provider
func (s *AuthService) protoToOAuthProvider(provider authv1.OAuthProvider) OAuthProvider {
	switch provider {
	case authv1.OAuthProvider_OAUTH_PROVIDER_GOOGLE:
		return ProviderGoogle
	case authv1.OAuthProvider_OAUTH_PROVIDER_GITHUB:
		return ProviderGitHub
	case authv1.OAuthProvider_OAUTH_PROVIDER_FACEBOOK:
		return ProviderFacebook
	case authv1.OAuthProvider_OAUTH_PROVIDER_APPLE:
		return ProviderApple
	case authv1.OAuthProvider_OAUTH_PROVIDER_MICROSOFT:
		return ProviderMicrosoft
	case authv1.OAuthProvider_OAUTH_PROVIDER_DISCORD:
		return ProviderDiscord
	default:
		return ""
	}
}
