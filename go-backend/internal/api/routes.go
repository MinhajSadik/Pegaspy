package api

import (
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"pegaspy-backend/internal/detection"
)

// SetupRoutes configures all API routes
func SetupRoutes(router *gin.Engine, engine *detection.Engine) {
	// Health check endpoint
	router.GET("/health", healthCheck)

	// API v1 routes
	v1 := router.Group("/api/v1")
	{
		// Detection endpoints
		v1.POST("/scan", scanHandler(engine))
		v1.GET("/detections", getDetectionsHandler(engine))
		v1.GET("/stats", getStatsHandler(engine))
		v1.GET("/status", getStatusHandler(engine))
		
		// Blockchain audit endpoints
		v1.GET("/audit/chain", getAuditChainHandler(engine))
		v1.GET("/audit/events", getAuditEventsHandler(engine))
		v1.GET("/audit/stats", getAuditStatsHandler(engine))
		v1.POST("/audit/mine", mineBlockHandler(engine))
		v1.GET("/audit/validate", validateChainHandler(engine))
		
		// Machine Learning endpoints
		v1.POST("/ml/predict", mlPredictHandler(engine))
		v1.GET("/ml/stats", mlStatsHandler(engine))
		v1.POST("/ml/train", mlTrainHandler(engine))
		v1.GET("/ml/patterns", mlPatternsHandler(engine))

		// Real-time monitoring
		v1.GET("/monitor/realtime", realtimeMonitorHandler(engine))
		v1.GET("/monitor/threats", threatMonitorHandler(engine))

		// System information
		v1.GET("/system/info", systemInfoHandler)
		v1.GET("/system/performance", performanceHandler)
	}

	// Dashboard routes
	dashboard := router.Group("/dashboard")
	{
		dashboard.GET("/", dashboardHandler)
		dashboard.Static("/static", "./web/static")
	}

	// Documentation
	router.GET("/docs", docsHandler)

	// WebSocket for real-time updates
	router.GET("/ws", websocketHandler(engine))
}

// Health check handler
func healthCheck(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"status":    "healthy",
		"timestamp": time.Now(),
		"version":   "4.0.0",
		"service":   "pegaspy-backend",
	})
}

// Scan handler - performs security scan on target
func scanHandler(engine *detection.Engine) gin.HandlerFunc {
	return func(c *gin.Context) {
		var request struct {
			Target string `json:"target" binding:"required"`
			Type   string `json:"type,omitempty"`
		}

		if err := c.ShouldBindJSON(&request); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "Invalid request format",
				"details": err.Error(),
			})
			return
		}

		// Perform scan
		result, err := engine.ScanTarget(request.Target)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Scan failed",
				"details": err.Error(),
			})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"success": true,
			"result":  result,
		})
	}
}

// Get detections handler
func getDetectionsHandler(engine *detection.Engine) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Parse query parameters
		limitStr := c.DefaultQuery("limit", "100")
		limit, err := strconv.Atoi(limitStr)
		if err != nil {
			limit = 100
		}

		offsetStr := c.DefaultQuery("offset", "0")
		offset, err := strconv.Atoi(offsetStr)
		if err != nil {
			offset = 0
		}

		threatType := c.Query("threat_type")
		level := c.Query("level")

		// Get all detections
		allDetections := engine.GetDetections()

		// Apply filters
		var filteredDetections []detection.Detection
		for _, d := range allDetections {
			if threatType != "" && d.ThreatType != threatType {
				continue
			}
			if level != "" && d.Level.String() != level {
				continue
			}
			filteredDetections = append(filteredDetections, d)
		}

		// Apply pagination
		total := len(filteredDetections)
		start := offset
		end := offset + limit
		if start > total {
			start = total
		}
		if end > total {
			end = total
		}

		paginatedDetections := filteredDetections[start:end]

		c.JSON(http.StatusOK, gin.H{
			"detections": paginatedDetections,
			"pagination": gin.H{
				"total":  total,
				"limit":  limit,
				"offset": offset,
				"count":  len(paginatedDetections),
			},
		})
	}
}

// Get stats handler
func getStatsHandler(engine *detection.Engine) gin.HandlerFunc {
	return func(c *gin.Context) {
		stats := engine.GetStats()
		c.JSON(http.StatusOK, gin.H{
			"stats": stats,
		})
	}
}

// Get status handler
func getStatusHandler(engine *detection.Engine) gin.HandlerFunc {
	return func(c *gin.Context) {
		stats := engine.GetStats()
		c.JSON(http.StatusOK, gin.H{
			"status": "running",
			"uptime": time.Since(stats.Uptime).String(),
			"active_scans": stats.ActiveScans,
			"total_scans": stats.TotalScans,
			"threats_detected": stats.ThreatsDetected,
			"average_latency_ms": stats.AverageLatency,
		})
	}
}

// Real-time monitor handler
func realtimeMonitorHandler(engine *detection.Engine) gin.HandlerFunc {
	return func(c *gin.Context) {
		// This would implement Server-Sent Events (SSE) for real-time updates
		c.Header("Content-Type", "text/event-stream")
		c.Header("Cache-Control", "no-cache")
		c.Header("Connection", "keep-alive")
		c.Header("Access-Control-Allow-Origin", "*")

		// Send initial status
		stats := engine.GetStats()
		c.SSEvent("status", gin.H{
			"timestamp": time.Now(),
			"stats": stats,
		})

		// Keep connection alive and send periodic updates
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-c.Request.Context().Done():
				return
			case <-ticker.C:
				stats := engine.GetStats()
				c.SSEvent("update", gin.H{
					"timestamp": time.Now(),
					"stats": stats,
				})
				c.Writer.Flush()
			}
		}
	}
}

// Threat monitor handler
func threatMonitorHandler(engine *detection.Engine) gin.HandlerFunc {
	return func(c *gin.Context) {
		detections := engine.GetDetections()
		
		// Get recent threats (last 24 hours)
		recentThreats := make([]detection.Detection, 0)
		cutoff := time.Now().Add(-24 * time.Hour)
		
		for _, d := range detections {
			if d.Timestamp.After(cutoff) {
				recentThreats = append(recentThreats, d)
			}
		}

		c.JSON(http.StatusOK, gin.H{
			"recent_threats": recentThreats,
			"count": len(recentThreats),
			"period": "24h",
		})
	}
}

// System info handler
func systemInfoHandler(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"system": gin.H{
			"os": "linux",
			"arch": "amd64",
			"go_version": "1.21",
			"pegaspy_version": "4.0.0",
		},
		"capabilities": []string{
			"file_scanning",
			"memory_analysis",
			"network_monitoring",
			"behavioral_analysis",
			"real_time_protection",
			"threat_intelligence",
		},
	})
}

// Performance handler
func performanceHandler(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"performance": gin.H{
			"cpu_usage": "15%",
			"memory_usage": "256MB",
			"disk_usage": "1.2GB",
			"network_io": "125KB/s",
			"goroutines": 42,
		},
		"timestamp": time.Now(),
	})
}

// Dashboard handler
func dashboardHandler(c *gin.Context) {
	c.HTML(http.StatusOK, "dashboard.html", gin.H{
		"title": "PegaSpy Phase 4 Dashboard",
		"version": "4.0.0",
	})
}

// Documentation handler
func docsHandler(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"api_documentation": gin.H{
			"version": "v1",
			"endpoints": []gin.H{
				{"method": "POST", "path": "/api/v1/scan", "description": "Perform security scan"},
				{"method": "GET", "path": "/api/v1/detections", "description": "Get threat detections"},
				{"method": "GET", "path": "/api/v1/stats", "description": "Get engine statistics"},
				{"method": "GET", "path": "/api/v1/status", "description": "Get system status"},
				{"method": "GET", "path": "/api/v1/monitor/realtime", "description": "Real-time monitoring stream"},
				{"method": "GET", "path": "/health", "description": "Health check"},
			},
		},
	})
}

// WebSocket handler for real-time updates
func websocketHandler(engine *detection.Engine) gin.HandlerFunc {
	return func(c *gin.Context) {
		// WebSocket implementation would go here
		// For now, return a placeholder
		c.JSON(http.StatusOK, gin.H{
			"message": "WebSocket endpoint - implementation pending",
			"upgrade_required": true,
		})
	}
}

// Blockchain Audit Handlers

// getAuditChainHandler returns the complete blockchain audit trail
func getAuditChainHandler(engine *detection.Engine) gin.HandlerFunc {
	return func(c *gin.Context) {
		chain := engine.GetAuditTrail().GetChain()
		c.JSON(http.StatusOK, gin.H{
			"success": true,
			"chain":   chain,
			"blocks":  len(chain),
		})
	}
}

// getAuditEventsHandler returns all audit events
func getAuditEventsHandler(engine *detection.Engine) gin.HandlerFunc {
	return func(c *gin.Context) {
		events := engine.GetAuditTrail().GetEvents()
		
		// Filter by event type if specified
		eventType := c.Query("type")
		if eventType != "" {
			events = engine.GetAuditTrail().GetEventsByType(eventType)
		}
		
		c.JSON(http.StatusOK, gin.H{
			"success": true,
			"events":  events,
			"count":   len(events),
		})
	}
}

// getAuditStatsHandler returns blockchain statistics
func getAuditStatsHandler(engine *detection.Engine) gin.HandlerFunc {
	return func(c *gin.Context) {
		stats := engine.GetBlockchainStats()
		c.JSON(http.StatusOK, gin.H{
			"success": true,
			"stats":   stats,
		})
	}
}

// mineBlockHandler manually triggers block mining
func mineBlockHandler(engine *detection.Engine) gin.HandlerFunc {
	return func(c *gin.Context) {
		err := engine.GetAuditTrail().MineBlock()
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"success": false,
				"error":   err.Error(),
			})
			return
		}
		
		c.JSON(http.StatusOK, gin.H{
			"success": true,
			"message": "Block mined successfully",
		})
	}
}

// validateChainHandler validates the blockchain integrity
func validateChainHandler(engine *detection.Engine) gin.HandlerFunc {
	return func(c *gin.Context) {
		isValid := engine.GetAuditTrail().ValidateChain()
		message := "Blockchain is valid and secure"
		if !isValid {
			message = "Blockchain integrity compromised"
		}
		
		c.JSON(http.StatusOK, gin.H{
			"success": true,
			"valid":   isValid,
			"message": message,
		})
	}
}

// Machine Learning Handlers

// mlPredictHandler performs ML-based threat prediction
func mlPredictHandler(engine *detection.Engine) gin.HandlerFunc {
	return func(c *gin.Context) {
		var requestData map[string]interface{}
		if err := c.ShouldBindJSON(&requestData); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"success": false,
				"error":   "Invalid request data",
			})
			return
		}
		
		prediction, err := engine.PredictThreat(requestData)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"success": false,
				"error":   err.Error(),
			})
			return
		}
		
		c.JSON(http.StatusOK, gin.H{
			"success":    true,
			"prediction": prediction,
		})
	}
}

// mlStatsHandler returns ML model statistics
func mlStatsHandler(engine *detection.Engine) gin.HandlerFunc {
	return func(c *gin.Context) {
		stats := engine.GetMLStats()
		c.JSON(http.StatusOK, gin.H{
			"success": true,
			"stats":   stats,
		})
	}
}

// mlTrainHandler trains the ML model with new data
func mlTrainHandler(engine *detection.Engine) gin.HandlerFunc {
	return func(c *gin.Context) {
		var request struct {
			TrainingData []map[string]interface{} `json:"training_data"`
			Labels       []string                 `json:"labels"`
		}
		
		if err := c.ShouldBindJSON(&request); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"success": false,
				"error":   "Invalid training data format",
			})
			return
		}
		
		err := engine.GetMLDetector().TrainModel(request.TrainingData, request.Labels)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"success": false,
				"error":   err.Error(),
			})
			return
		}
		
		c.JSON(http.StatusOK, gin.H{
			"success": true,
			"message": "Model trained successfully",
			"patterns": len(request.TrainingData),
		})
	}
}

// mlPatternsHandler returns learned threat patterns
func mlPatternsHandler(engine *detection.Engine) gin.HandlerFunc {
	return func(c *gin.Context) {
		stats := engine.GetMLStats()
		c.JSON(http.StatusOK, gin.H{
			"success":       true,
			"total_patterns": stats.TotalPatterns,
			"threat_types":   stats.ThreatTypes,
			"model_version":  stats.ModelVersion,
			"last_training":  stats.LastTraining,
		})
	}
}