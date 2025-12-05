package main

import (
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"

	authv1 "github.com/guipguia/api/proto/auth/v1"
	"github.com/guipguia/internal/config"
	"github.com/guipguia/internal/database"
	"github.com/guipguia/internal/repository"
	"github.com/guipguia/internal/service"
)

func main() {
	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Initialize database
	db, err := database.New(&cfg.Database)
	if err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}
	defer db.Close()

	// Run migrations
	if err := db.AutoMigrate(); err != nil {
		log.Fatalf("Failed to run migrations: %v", err)
	}

	// Test database connection
	if err := db.Ping(); err != nil {
		log.Fatalf("Failed to ping database: %v", err)
	}

	log.Println("Database connection established successfully")

	// Initialize cache service for stateless horizontal scaling
	cacheService, err := service.NewCacheService(&cfg.Cache)
	if err != nil {
		log.Fatalf("Failed to initialize cache service: %v", err)
	}
	defer cacheService.Close()

	if cfg.Cache.Enabled {
		log.Printf("Cache service initialized (type: %s)", cfg.Cache.Type)
	} else {
		log.Println("Cache disabled - running in stateless mode")
	}

	// Initialize repositories (with caching if enabled)
	userRepo := repository.NewUserRepository(db.DB)
	var sessionRepo repository.SessionRepository
	var otpRepo repository.OTPRepository

	if cfg.Cache.Enabled {
		sessionRepo = repository.NewCachedSessionRepository(db.DB, cacheService, cfg.Cache.TTLSeconds)
		otpRepo = repository.NewCachedOTPRepository(db.DB, cacheService, cfg.Cache.TTLSeconds)
	} else {
		sessionRepo = repository.NewSessionRepository(db.DB)
		otpRepo = repository.NewOTPRepository(db.DB)
	}

	// Initialize services
	passwordService := service.NewPasswordService()
	totpService := service.NewTOTPService()
	passwordlessService := service.NewPasswordlessService(otpRepo)
	oauthService := service.NewOAuthService(&cfg.OAuth)
	jwtService := service.NewJWTService(&cfg.JWT)
	emailService := service.NewEmailService(&cfg.Email, cfg.Server.AppURL)

	// Initialize auth service
	authService := service.NewAuthService(
		userRepo,
		sessionRepo,
		otpRepo,
		passwordService,
		totpService,
		passwordlessService,
		oauthService,
		jwtService,
		emailService,
	)

	// Create gRPC server
	grpcServer := grpc.NewServer(
		grpc.UnaryInterceptor(service.UnaryAuthInterceptor()),
	)

	// Register service
	authv1.RegisterAuthServiceServer(grpcServer, authService)

	// Enable reflection for grpcurl
	reflection.Register(grpcServer)

	// Start server
	listener, err := net.Listen("tcp", cfg.Server.Address)
	if err != nil {
		log.Fatalf("Failed to listen: %v", err)
	}

	log.Printf("Auth service listening on %s", cfg.Server.Address)

	// Graceful shutdown
	go func() {
		if err := grpcServer.Serve(listener); err != nil {
			log.Fatalf("Failed to serve: %v", err)
		}
	}()

	// Wait for interrupt signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("Shutting down server...")
	grpcServer.GracefulStop()
}
