package config

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/viper"
)

// Config holds all configuration for the auth service
type Config struct {
	Server   ServerConfig
	Database DatabaseConfig
	JWT      JWTConfig
	OAuth    OAuthConfig
	Email    EmailConfig
}

// ServerConfig holds server-related configuration
type ServerConfig struct {
	Address string
	Port    int
	AppURL  string // Base URL for the application (used in email links)
}

// DatabaseConfig holds database connection configuration
type DatabaseConfig struct {
	Host     string
	Port     int
	User     string
	Password string
	DBName   string
	SSLMode  string
	MaxConns int
	MaxIdle  int
}

// JWTConfig holds JWT token configuration
type JWTConfig struct {
	AccessTokenSecret  string
	RefreshTokenSecret string
	AccessTokenExpiry  time.Duration
	RefreshTokenExpiry time.Duration
	Issuer             string
}

// OAuthConfig holds OAuth provider configurations
type OAuthConfig struct {
	Google    OAuthProviderConfig
	GitHub    OAuthProviderConfig
	Facebook  OAuthProviderConfig
	Apple     OAuthProviderConfig
	Microsoft OAuthProviderConfig
	Discord   OAuthProviderConfig
}

// OAuthProviderConfig holds configuration for a single OAuth provider
type OAuthProviderConfig struct {
	ClientID     string
	ClientSecret string
	RedirectURL  string
	Scopes       []string
}

// EmailConfig holds email service configuration
type EmailConfig struct {
	Provider  string // smtp, sendgrid, ses
	SMTPHost  string
	SMTPPort  int
	SMTPUser  string
	SMTPPass  string
	FromEmail string
	FromName  string
	APIKey    string // For sendgrid/ses
}

// Load reads configuration from environment variables and config files
func Load() (*Config, error) {
	v := viper.New()

	// Set defaults
	setDefaults(v)

	// Configure environment variable handling
	v.SetEnvPrefix("AUTH")
	v.AutomaticEnv()
	// Replace dots with underscores in env var names (e.g., database.host -> DATABASE_HOST)
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

	// Bind all environment variables explicitly
	bindEnvVariables(v)

	// Try to read config file if it exists
	v.SetConfigName("config")
	v.SetConfigType("yaml")
	v.AddConfigPath("./config")
	v.AddConfigPath(".")

	if err := v.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, fmt.Errorf("failed to read config file: %w", err)
		}
		// Config file not found, will use env vars and defaults
	}

	cfg := &Config{
		Server: ServerConfig{
			Address: v.GetString("server.address"),
			Port:    v.GetInt("server.port"),
			AppURL:  v.GetString("server.app_url"),
		},
		Database: DatabaseConfig{
			Host:     v.GetString("database.host"),
			Port:     v.GetInt("database.port"),
			User:     v.GetString("database.user"),
			Password: v.GetString("database.password"),
			DBName:   v.GetString("database.dbname"),
			SSLMode:  v.GetString("database.sslmode"),
			MaxConns: v.GetInt("database.max_conns"),
			MaxIdle:  v.GetInt("database.max_idle"),
		},
		JWT: JWTConfig{
			AccessTokenSecret:  v.GetString("jwt.access_token_secret"),
			RefreshTokenSecret: v.GetString("jwt.refresh_token_secret"),
			AccessTokenExpiry:  v.GetDuration("jwt.access_token_expiry"),
			RefreshTokenExpiry: v.GetDuration("jwt.refresh_token_expiry"),
			Issuer:             v.GetString("jwt.issuer"),
		},
		OAuth: OAuthConfig{
			Google: OAuthProviderConfig{
				ClientID:     v.GetString("oauth.google.client_id"),
				ClientSecret: v.GetString("oauth.google.client_secret"),
				RedirectURL:  v.GetString("oauth.google.redirect_url"),
				Scopes:       v.GetStringSlice("oauth.google.scopes"),
			},
			GitHub: OAuthProviderConfig{
				ClientID:     v.GetString("oauth.github.client_id"),
				ClientSecret: v.GetString("oauth.github.client_secret"),
				RedirectURL:  v.GetString("oauth.github.redirect_url"),
				Scopes:       v.GetStringSlice("oauth.github.scopes"),
			},
			Facebook: OAuthProviderConfig{
				ClientID:     v.GetString("oauth.facebook.client_id"),
				ClientSecret: v.GetString("oauth.facebook.client_secret"),
				RedirectURL:  v.GetString("oauth.facebook.redirect_url"),
				Scopes:       v.GetStringSlice("oauth.facebook.scopes"),
			},
			Apple: OAuthProviderConfig{
				ClientID:     v.GetString("oauth.apple.client_id"),
				ClientSecret: v.GetString("oauth.apple.client_secret"),
				RedirectURL:  v.GetString("oauth.apple.redirect_url"),
				Scopes:       v.GetStringSlice("oauth.apple.scopes"),
			},
			Microsoft: OAuthProviderConfig{
				ClientID:     v.GetString("oauth.microsoft.client_id"),
				ClientSecret: v.GetString("oauth.microsoft.client_secret"),
				RedirectURL:  v.GetString("oauth.microsoft.redirect_url"),
				Scopes:       v.GetStringSlice("oauth.microsoft.scopes"),
			},
			Discord: OAuthProviderConfig{
				ClientID:     v.GetString("oauth.discord.client_id"),
				ClientSecret: v.GetString("oauth.discord.client_secret"),
				RedirectURL:  v.GetString("oauth.discord.redirect_url"),
				Scopes:       v.GetStringSlice("oauth.discord.scopes"),
			},
		},
		Email: EmailConfig{
			Provider:  v.GetString("email.provider"),
			SMTPHost:  v.GetString("email.smtp_host"),
			SMTPPort:  v.GetInt("email.smtp_port"),
			SMTPUser:  v.GetString("email.smtp_user"),
			SMTPPass:  v.GetString("email.smtp_pass"),
			FromEmail: v.GetString("email.from_email"),
			FromName:  v.GetString("email.from_name"),
			APIKey:    v.GetString("email.api_key"),
		},
	}

	// Validate required fields
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	return cfg, nil
}

// bindEnvVariables explicitly binds all config keys to environment variables
func bindEnvVariables(v *viper.Viper) {
	// Server
	v.BindEnv("server.address")
	v.BindEnv("server.port")
	v.BindEnv("server.app_url")

	// Database
	v.BindEnv("database.host")
	v.BindEnv("database.port")
	v.BindEnv("database.user")
	v.BindEnv("database.password")
	v.BindEnv("database.dbname")
	v.BindEnv("database.sslmode")
	v.BindEnv("database.max_conns")
	v.BindEnv("database.max_idle")

	// JWT
	v.BindEnv("jwt.access_token_secret")
	v.BindEnv("jwt.refresh_token_secret")
	v.BindEnv("jwt.access_token_expiry")
	v.BindEnv("jwt.refresh_token_expiry")
	v.BindEnv("jwt.issuer")

	// OAuth - Google
	v.BindEnv("oauth.google.client_id")
	v.BindEnv("oauth.google.client_secret")
	v.BindEnv("oauth.google.redirect_url")
	v.BindEnv("oauth.google.scopes")

	// OAuth - GitHub
	v.BindEnv("oauth.github.client_id")
	v.BindEnv("oauth.github.client_secret")
	v.BindEnv("oauth.github.redirect_url")
	v.BindEnv("oauth.github.scopes")

	// OAuth - Facebook
	v.BindEnv("oauth.facebook.client_id")
	v.BindEnv("oauth.facebook.client_secret")
	v.BindEnv("oauth.facebook.redirect_url")
	v.BindEnv("oauth.facebook.scopes")

	// OAuth - Apple
	v.BindEnv("oauth.apple.client_id")
	v.BindEnv("oauth.apple.client_secret")
	v.BindEnv("oauth.apple.redirect_url")
	v.BindEnv("oauth.apple.scopes")

	// OAuth - Microsoft
	v.BindEnv("oauth.microsoft.client_id")
	v.BindEnv("oauth.microsoft.client_secret")
	v.BindEnv("oauth.microsoft.redirect_url")
	v.BindEnv("oauth.microsoft.scopes")

	// OAuth - Discord
	v.BindEnv("oauth.discord.client_id")
	v.BindEnv("oauth.discord.client_secret")
	v.BindEnv("oauth.discord.redirect_url")
	v.BindEnv("oauth.discord.scopes")

	// Email
	v.BindEnv("email.provider")
	v.BindEnv("email.smtp_host")
	v.BindEnv("email.smtp_port")
	v.BindEnv("email.smtp_user")
	v.BindEnv("email.smtp_pass")
	v.BindEnv("email.from_email")
	v.BindEnv("email.from_name")
	v.BindEnv("email.api_key")
}

// setDefaults sets default configuration values
func setDefaults(v *viper.Viper) {
	// Server defaults
	v.SetDefault("server.address", ":8080")
	v.SetDefault("server.port", 8080)
	v.SetDefault("server.app_url", "http://localhost:3000")

	// Database defaults
	v.SetDefault("database.host", "localhost")
	v.SetDefault("database.port", 5432)
	v.SetDefault("database.user", "postgres")
	v.SetDefault("database.password", "postgres")
	v.SetDefault("database.dbname", "auth_db")
	v.SetDefault("database.sslmode", "disable")
	v.SetDefault("database.max_conns", 25)
	v.SetDefault("database.max_idle", 5)

	// JWT defaults
	v.SetDefault("jwt.access_token_expiry", 15*time.Minute)
	v.SetDefault("jwt.refresh_token_expiry", 7*24*time.Hour)
	v.SetDefault("jwt.issuer", "auth-service")

	// Email defaults
	v.SetDefault("email.provider", "smtp")
	v.SetDefault("email.smtp_port", 587)
	v.SetDefault("email.from_name", "Auth Service")

	// OAuth defaults
	v.SetDefault("oauth.google.scopes", []string{"openid", "email", "profile"})
	v.SetDefault("oauth.github.scopes", []string{"user:email"})
	v.SetDefault("oauth.facebook.scopes", []string{"email", "public_profile"})
	v.SetDefault("oauth.apple.scopes", []string{"email", "name"})
	v.SetDefault("oauth.microsoft.scopes", []string{"openid", "email", "profile"})
	v.SetDefault("oauth.discord.scopes", []string{"identify", "email"})
}

// Validate checks if required configuration values are present
func (c *Config) Validate() error {
	if c.JWT.AccessTokenSecret == "" {
		if secret := os.Getenv("AUTH_JWT_ACCESS_TOKEN_SECRET"); secret != "" {
			c.JWT.AccessTokenSecret = secret
		} else {
			return fmt.Errorf("JWT access token secret is required")
		}
	}

	if c.JWT.RefreshTokenSecret == "" {
		if secret := os.Getenv("AUTH_JWT_REFRESH_TOKEN_SECRET"); secret != "" {
			c.JWT.RefreshTokenSecret = secret
		} else {
			return fmt.Errorf("JWT refresh token secret is required")
		}
	}

	if c.Database.Host == "" {
		return fmt.Errorf("database host is required")
	}

	return nil
}
