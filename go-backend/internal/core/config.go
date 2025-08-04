package core

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strconv"
)

// Config holds the application configuration
type Config struct {
	Port                int    `json:"port"`
	Host                string `json:"host"`
	LogLevel            string `json:"log_level"`
	DatabaseURL         string `json:"database_url"`
	RedisURL            string `json:"redis_url"`
	JWTSecret           string `json:"jwt_secret"`
	DetectionEnabled    bool   `json:"detection_enabled"`
	RealtimeMonitoring  bool   `json:"realtime_monitoring"`
	ThreatIntelEnabled  bool   `json:"threat_intel_enabled"`
	MaxConcurrentScans  int    `json:"max_concurrent_scans"`
	ScanTimeout         int    `json:"scan_timeout_seconds"`
	APIRateLimit        int    `json:"api_rate_limit"`
	SecurityMode        string `json:"security_mode"`
	EncryptionEnabled   bool   `json:"encryption_enabled"`
	AuditLogging        bool   `json:"audit_logging"`
	BlockchainEnabled   bool   `json:"blockchain_enabled"`
	CloudDeployment     bool   `json:"cloud_deployment"`
}

// LoadConfig loads configuration from environment variables and config file
func LoadConfig() *Config {
	config := &Config{
		// Default values
		Port:                8080,
		Host:                "0.0.0.0",
		LogLevel:            "info",
		DatabaseURL:         "postgres://localhost/pegaspy?sslmode=disable",
		RedisURL:            "redis://localhost:6379",
		JWTSecret:           "pegaspy-jwt-secret-change-in-production",
		DetectionEnabled:    true,
		RealtimeMonitoring:  true,
		ThreatIntelEnabled:  true,
		MaxConcurrentScans:  10,
		ScanTimeout:         300,
		APIRateLimit:        1000,
		SecurityMode:        "strict",
		EncryptionEnabled:   true,
		AuditLogging:        true,
		BlockchainEnabled:   false,
		CloudDeployment:     false,
	}

	// Load from config file if exists
	if configFile := os.Getenv("PEGASPY_CONFIG_FILE"); configFile != "" {
		if data, err := os.ReadFile(configFile); err == nil {
			if err := json.Unmarshal(data, config); err != nil {
				log.Printf("Warning: Failed to parse config file: %v", err)
			}
		}
	}

	// Override with environment variables
	if port := os.Getenv("PEGASPY_PORT"); port != "" {
		if p, err := strconv.Atoi(port); err == nil {
			config.Port = p
		}
	}

	if host := os.Getenv("PEGASPY_HOST"); host != "" {
		config.Host = host
	}

	if logLevel := os.Getenv("PEGASPY_LOG_LEVEL"); logLevel != "" {
		config.LogLevel = logLevel
	}

	if dbURL := os.Getenv("PEGASPY_DATABASE_URL"); dbURL != "" {
		config.DatabaseURL = dbURL
	}

	if redisURL := os.Getenv("PEGASPY_REDIS_URL"); redisURL != "" {
		config.RedisURL = redisURL
	}

	if jwtSecret := os.Getenv("PEGASPY_JWT_SECRET"); jwtSecret != "" {
		config.JWTSecret = jwtSecret
	}

	if secMode := os.Getenv("PEGASPY_SECURITY_MODE"); secMode != "" {
		config.SecurityMode = secMode
	}

	// Boolean environment variables
	if detection := os.Getenv("PEGASPY_DETECTION_ENABLED"); detection != "" {
		config.DetectionEnabled = detection == "true"
	}

	if realtime := os.Getenv("PEGASPY_REALTIME_MONITORING"); realtime != "" {
		config.RealtimeMonitoring = realtime == "true"
	}

	if threatIntel := os.Getenv("PEGASPY_THREAT_INTEL_ENABLED"); threatIntel != "" {
		config.ThreatIntelEnabled = threatIntel == "true"
	}

	if encryption := os.Getenv("PEGASPY_ENCRYPTION_ENABLED"); encryption != "" {
		config.EncryptionEnabled = encryption == "true"
	}

	if audit := os.Getenv("PEGASPY_AUDIT_LOGGING"); audit != "" {
		config.AuditLogging = audit == "true"
	}

	if blockchain := os.Getenv("PEGASPY_BLOCKCHAIN_ENABLED"); blockchain != "" {
		config.BlockchainEnabled = blockchain == "true"
	}

	if cloud := os.Getenv("PEGASPY_CLOUD_DEPLOYMENT"); cloud != "" {
		config.CloudDeployment = cloud == "true"
	}

	// Integer environment variables
	if maxScans := os.Getenv("PEGASPY_MAX_CONCURRENT_SCANS"); maxScans != "" {
		if m, err := strconv.Atoi(maxScans); err == nil {
			config.MaxConcurrentScans = m
		}
	}

	if timeout := os.Getenv("PEGASPY_SCAN_TIMEOUT"); timeout != "" {
		if t, err := strconv.Atoi(timeout); err == nil {
			config.ScanTimeout = t
		}
	}

	if rateLimit := os.Getenv("PEGASPY_API_RATE_LIMIT"); rateLimit != "" {
		if r, err := strconv.Atoi(rateLimit); err == nil {
			config.APIRateLimit = r
		}
	}

	log.Printf("📋 Configuration loaded:")
	log.Printf("   Port: %d", config.Port)
	log.Printf("   Host: %s", config.Host)
	log.Printf("   Security Mode: %s", config.SecurityMode)
	log.Printf("   Detection Enabled: %v", config.DetectionEnabled)
	log.Printf("   Realtime Monitoring: %v", config.RealtimeMonitoring)
	log.Printf("   Max Concurrent Scans: %d", config.MaxConcurrentScans)

	return config
}

// Validate checks if the configuration is valid
func (c *Config) Validate() error {
	if c.Port < 1 || c.Port > 65535 {
		return fmt.Errorf("invalid port: %d", c.Port)
	}

	if c.MaxConcurrentScans < 1 {
		return fmt.Errorf("max concurrent scans must be at least 1")
	}

	if c.ScanTimeout < 1 {
		return fmt.Errorf("scan timeout must be at least 1 second")
	}

	if c.APIRateLimit < 1 {
		return fmt.Errorf("API rate limit must be at least 1")
	}

	return nil
}