package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"pegaspy-backend/internal/api"
	"pegaspy-backend/internal/core"
	"pegaspy-backend/internal/detection"
)

func main() {
	log.Println("🕷️ PegaSpy Phase 4 - High-Performance Backend Server")
	log.Println("=============================================")

	// Initialize core components
	config := core.LoadConfig()
	detectionEngine := detection.NewEngine(config)

	// Start detection engine
	if err := detectionEngine.Start(); err != nil {
		log.Fatalf("Failed to start detection engine: %v", err)
	}
	defer detectionEngine.Stop()

	// Setup Gin router
	router := gin.New()
	router.Use(gin.Logger())
	router.Use(gin.Recovery())

	// Setup API routes
	api.SetupRoutes(router, detectionEngine)

	// Create HTTP server
	srv := &http.Server{
		Addr:         fmt.Sprintf(":%d", config.Port),
		Handler:      router,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Start server in goroutine
	go func() {
		log.Printf("🚀 Server starting on port %d", config.Port)
		log.Printf("📊 Dashboard: http://localhost:%d/dashboard", config.Port)
		log.Printf("🔍 API Docs: http://localhost:%d/docs", config.Port)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Failed to start server: %v", err)
		}
	}()

	// Wait for interrupt signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("🛑 Shutting down server...")

	// Graceful shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		log.Fatalf("Server forced to shutdown: %v", err)
	}

	log.Println("✅ Server exited gracefully")
}