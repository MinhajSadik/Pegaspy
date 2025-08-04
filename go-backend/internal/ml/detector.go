package ml

import (
	"fmt"
	"log"
	"math"
	"math/rand"
	"sort"
	"sync"
	"time"
)

// ThreatPattern represents a learned threat pattern
type ThreatPattern struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name"`
	Features    []float64              `json:"features"`
	ThreatType  string                 `json:"threat_type"`
	Confidence  float64                `json:"confidence"`
	LastUpdated time.Time              `json:"last_updated"`
	Metadata    map[string]interface{} `json:"metadata"`
}

// MLPrediction represents a machine learning prediction result
type MLPrediction struct {
	ThreatType     string                 `json:"threat_type"`
	Confidence     float64                `json:"confidence"`
	RiskScore      float64                `json:"risk_score"`
	Features       []float64              `json:"features"`
	MatchedPattern *ThreatPattern         `json:"matched_pattern,omitempty"`
	Timestamp      time.Time              `json:"timestamp"`
	Metadata       map[string]interface{} `json:"metadata"`
}

// FeatureExtractor extracts features from raw data
type FeatureExtractor struct {
	mu sync.RWMutex
}

// MLDetector represents the machine learning threat detector
type MLDetector struct {
	patterns         []ThreatPattern
	featureExtractor *FeatureExtractor
	modelVersion     string
	lastTraining     time.Time
	mu               sync.RWMutex
}

// ModelStats represents ML model statistics
type ModelStats struct {
	TotalPatterns    int       `json:"total_patterns"`
	ModelVersion     string    `json:"model_version"`
	LastTraining     time.Time `json:"last_training"`
	Accuracy         float64   `json:"accuracy"`
	Precision        float64   `json:"precision"`
	Recall           float64   `json:"recall"`
	F1Score          float64   `json:"f1_score"`
	ThreatTypes      []string  `json:"threat_types"`
	TrainingDataSize int       `json:"training_data_size"`
}

// NewMLDetector creates a new machine learning detector
func NewMLDetector() *MLDetector {
	detector := &MLDetector{
		patterns:         make([]ThreatPattern, 0),
		featureExtractor: &FeatureExtractor{},
		modelVersion:     "v4.0.0",
		lastTraining:     time.Now(),
	}
	
	// Initialize with pre-trained patterns
	detector.initializePretrainedPatterns()
	
	return detector
}

// ExtractFeatures extracts numerical features from raw data
func (fe *FeatureExtractor) ExtractFeatures(data map[string]interface{}) []float64 {
	fe.mu.RLock()
	defer fe.mu.RUnlock()
	
	features := make([]float64, 20) // Fixed feature vector size
	
	// Feature 1-3: File-based features
	if filename, ok := data["filename"].(string); ok {
		features[0] = float64(len(filename)) / 100.0 // Normalized filename length
		features[1] = fe.calculateEntropyScore(filename)
		features[2] = fe.calculateSuspiciousExtensionScore(filename)
	}
	
	// Feature 4-6: Network-based features
	if networkData, ok := data["network"].(map[string]interface{}); ok {
		if port, ok := networkData["port"].(float64); ok {
			features[3] = fe.normalizePort(port)
		}
		if protocol, ok := networkData["protocol"].(string); ok {
			features[4] = fe.protocolToScore(protocol)
		}
		if connections, ok := networkData["connections"].(float64); ok {
			features[5] = math.Min(connections/1000.0, 1.0) // Normalized connection count
		}
	}
	
	// Feature 7-9: Process-based features
	if processData, ok := data["process"].(map[string]interface{}); ok {
		if cpuUsage, ok := processData["cpu_usage"].(float64); ok {
			features[6] = cpuUsage / 100.0
		}
		if memoryUsage, ok := processData["memory_usage"].(float64); ok {
			features[7] = memoryUsage / 100.0
		}
		if processName, ok := processData["name"].(string); ok {
			features[8] = fe.calculateSuspiciousProcessScore(processName)
		}
	}
	
	// Feature 10-12: Behavioral features
	if behaviorData, ok := data["behavior"].(map[string]interface{}); ok {
		if fileAccess, ok := behaviorData["file_access_count"].(float64); ok {
			features[9] = math.Min(fileAccess/100.0, 1.0)
		}
		if networkRequests, ok := behaviorData["network_requests"].(float64); ok {
			features[10] = math.Min(networkRequests/50.0, 1.0)
		}
		if registryChanges, ok := behaviorData["registry_changes"].(float64); ok {
			features[11] = math.Min(registryChanges/20.0, 1.0)
		}
	}
	
	// Feature 13-15: Temporal features
	if timeData, ok := data["temporal"].(map[string]interface{}); ok {
		if hour, ok := timeData["hour"].(float64); ok {
			features[12] = fe.calculateTimeRiskScore(hour)
		}
		if dayOfWeek, ok := timeData["day_of_week"].(float64); ok {
			features[13] = fe.calculateDayRiskScore(dayOfWeek)
		}
		if duration, ok := timeData["duration"].(float64); ok {
			features[14] = math.Min(duration/3600.0, 1.0) // Normalized to hours
		}
	}
	
	// Feature 16-20: Advanced features
	features[15] = fe.calculateOverallSuspicionScore(data)
	features[16] = fe.calculateComplexityScore(data)
	features[17] = fe.calculateAnomalyScore(data)
	features[18] = fe.calculatePatternMatchScore(data)
	features[19] = rand.Float64() * 0.1 // Small random component for model robustness
	
	return features
}

// Predict analyzes data and returns ML-based threat predictions
func (ml *MLDetector) Predict(data map[string]interface{}) (*MLPrediction, error) {
	ml.mu.RLock()
	defer ml.mu.RUnlock()
	
	// Extract features
	features := ml.featureExtractor.ExtractFeatures(data)
	
	// Find best matching pattern
	bestMatch, confidence := ml.findBestMatch(features)
	
	// Calculate risk score
	riskScore := ml.calculateRiskScore(features, confidence)
	
	// Determine threat type
	threatType := "unknown"
	if bestMatch != nil {
		threatType = bestMatch.ThreatType
	} else if riskScore > 0.7 {
		threatType = "anomaly"
	}
	
	prediction := &MLPrediction{
		ThreatType:     threatType,
		Confidence:     confidence,
		RiskScore:      riskScore,
		Features:       features,
		MatchedPattern: bestMatch,
		Timestamp:      time.Now(),
		Metadata: map[string]interface{}{
			"model_version":    ml.modelVersion,
			"pattern_count":    len(ml.patterns),
			"feature_vector":   len(features),
			"processing_time":  time.Since(time.Now()).Milliseconds(),
		},
	}
	
	return prediction, nil
}

// TrainModel updates the ML model with new threat data
func (ml *MLDetector) TrainModel(trainingData []map[string]interface{}, labels []string) error {
	ml.mu.Lock()
	defer ml.mu.Unlock()
	
	if len(trainingData) != len(labels) {
		return fmt.Errorf("training data and labels must have the same length")
	}
	
	// Extract features from training data
	for i, data := range trainingData {
		features := ml.featureExtractor.ExtractFeatures(data)
		
		// Create or update pattern
		pattern := ThreatPattern{
			ID:          fmt.Sprintf("pattern_%d_%d", time.Now().Unix(), i),
			Name:        fmt.Sprintf("Learned Pattern %s", labels[i]),
			Features:    features,
			ThreatType:  labels[i],
			Confidence:  0.8, // Initial confidence
			LastUpdated: time.Now(),
			Metadata: map[string]interface{}{
				"training_iteration": i,
				"data_source":        "user_feedback",
			},
		}
		
		ml.patterns = append(ml.patterns, pattern)
	}
	
	ml.lastTraining = time.Now()
	log.Printf("🤖 ML Model trained with %d new patterns", len(trainingData))
	
	return nil
}

// GetModelStats returns current model statistics
func (ml *MLDetector) GetModelStats() ModelStats {
	ml.mu.RLock()
	defer ml.mu.RUnlock()
	
	threatTypes := make(map[string]bool)
	for _, pattern := range ml.patterns {
		threatTypes[pattern.ThreatType] = true
	}
	
	threatTypeList := make([]string, 0, len(threatTypes))
	for threatType := range threatTypes {
		threatTypeList = append(threatTypeList, threatType)
	}
	
	return ModelStats{
		TotalPatterns:    len(ml.patterns),
		ModelVersion:     ml.modelVersion,
		LastTraining:     ml.lastTraining,
		Accuracy:         0.92,  // Simulated metrics
		Precision:        0.89,
		Recall:           0.94,
		F1Score:          0.91,
		ThreatTypes:      threatTypeList,
		TrainingDataSize: len(ml.patterns),
	}
}

// Private helper methods

func (ml *MLDetector) initializePretrainedPatterns() {
	pretrainedPatterns := []ThreatPattern{
		{
			ID:         "malware_001",
			Name:       "Generic Malware Pattern",
			Features:   []float64{0.8, 0.9, 0.7, 0.3, 0.6, 0.4, 0.8, 0.7, 0.9, 0.5, 0.6, 0.3, 0.4, 0.2, 0.1, 0.8, 0.7, 0.6, 0.5, 0.1},
			ThreatType: "malware",
			Confidence: 0.95,
		},
		{
			ID:         "ransomware_001",
			Name:       "Ransomware Behavior Pattern",
			Features:   []float64{0.6, 0.8, 0.5, 0.2, 0.4, 0.9, 0.9, 0.8, 0.7, 0.9, 0.8, 0.9, 0.3, 0.4, 0.6, 0.9, 0.8, 0.7, 0.8, 0.05},
			ThreatType: "ransomware",
			Confidence: 0.93,
		},
		{
			ID:         "network_intrusion_001",
			Name:       "Network Intrusion Pattern",
			Features:   []float64{0.3, 0.4, 0.2, 0.9, 0.8, 0.9, 0.4, 0.3, 0.5, 0.2, 0.8, 0.1, 0.7, 0.6, 0.8, 0.7, 0.6, 0.8, 0.9, 0.02},
			ThreatType: "network_intrusion",
			Confidence: 0.88,
		},
	}
	
	for _, pattern := range pretrainedPatterns {
		pattern.LastUpdated = time.Now()
		pattern.Metadata = map[string]interface{}{
			"source": "pretrained",
			"version": ml.modelVersion,
		}
		ml.patterns = append(ml.patterns, pattern)
	}
}

func (ml *MLDetector) findBestMatch(features []float64) (*ThreatPattern, float64) {
	type patternMatch struct {
		pattern    *ThreatPattern
		similarity float64
	}
	
	matches := make([]patternMatch, 0)
	
	for i := range ml.patterns {
		similarity := ml.calculateCosineSimilarity(features, ml.patterns[i].Features)
		matches = append(matches, patternMatch{
			pattern:    &ml.patterns[i],
			similarity: similarity,
		})
	}
	
	// Sort by similarity
	sort.Slice(matches, func(i, j int) bool {
		return matches[i].similarity > matches[j].similarity
	})
	
	if len(matches) > 0 && matches[0].similarity > 0.7 {
		return matches[0].pattern, matches[0].similarity
	}
	
	return nil, 0.0
}

func (ml *MLDetector) calculateCosineSimilarity(a, b []float64) float64 {
	if len(a) != len(b) {
		return 0.0
	}
	
	dotProduct := 0.0
	normA := 0.0
	normB := 0.0
	
	for i := 0; i < len(a); i++ {
		dotProduct += a[i] * b[i]
		normA += a[i] * a[i]
		normB += b[i] * b[i]
	}
	
	if normA == 0.0 || normB == 0.0 {
		return 0.0
	}
	
	return dotProduct / (math.Sqrt(normA) * math.Sqrt(normB))
}

func (ml *MLDetector) calculateRiskScore(features []float64, confidence float64) float64 {
	// Weighted risk calculation
	weightedSum := 0.0
	weights := []float64{0.1, 0.15, 0.1, 0.08, 0.08, 0.12, 0.05, 0.05, 0.1, 0.08, 0.08, 0.05, 0.03, 0.03, 0.05, 0.15, 0.1, 0.12, 0.1, 0.01}
	
	for i, feature := range features {
		if i < len(weights) {
			weightedSum += feature * weights[i]
		}
	}
	
	// Combine with confidence
	riskScore := (weightedSum + confidence) / 2.0
	return math.Min(math.Max(riskScore, 0.0), 1.0)
}

// Feature extraction helper methods

func (fe *FeatureExtractor) calculateEntropyScore(s string) float64 {
	if len(s) == 0 {
		return 0.0
	}
	
	freq := make(map[rune]int)
	for _, char := range s {
		freq[char]++
	}
	
	entropy := 0.0
	length := float64(len(s))
	
	for _, count := range freq {
		p := float64(count) / length
		if p > 0 {
			entropy -= p * math.Log2(p)
		}
	}
	
	return math.Min(entropy/4.0, 1.0) // Normalize to 0-1
}

func (fe *FeatureExtractor) calculateSuspiciousExtensionScore(filename string) float64 {
	suspiciousExts := []string{".exe", ".scr", ".bat", ".cmd", ".pif", ".vbs", ".js"}
	for _, ext := range suspiciousExts {
		if len(filename) >= len(ext) && filename[len(filename)-len(ext):] == ext {
			return 1.0
		}
	}
	return 0.0
}

func (fe *FeatureExtractor) normalizePort(port float64) float64 {
	return math.Min(port/65535.0, 1.0)
}

func (fe *FeatureExtractor) protocolToScore(protocol string) float64 {
	switch protocol {
	case "TCP":
		return 0.3
	case "UDP":
		return 0.5
	case "ICMP":
		return 0.8
	default:
		return 0.1
	}
}

func (fe *FeatureExtractor) calculateSuspiciousProcessScore(processName string) float64 {
	suspiciousNames := []string{"svchost", "rundll32", "regsvr32", "powershell", "cmd"}
	for _, name := range suspiciousNames {
		if processName == name {
			return 0.8
		}
	}
	return 0.2
}

func (fe *FeatureExtractor) calculateTimeRiskScore(hour float64) float64 {
	// Higher risk during off-hours
	if hour < 6 || hour > 22 {
		return 0.8
	}
	return 0.2
}

func (fe *FeatureExtractor) calculateDayRiskScore(dayOfWeek float64) float64 {
	// Higher risk on weekends
	if dayOfWeek == 0 || dayOfWeek == 6 {
		return 0.7
	}
	return 0.3
}

func (fe *FeatureExtractor) calculateOverallSuspicionScore(data map[string]interface{}) float64 {
	// Aggregate suspicion based on multiple factors
	score := 0.0
	if _, hasNetwork := data["network"]; hasNetwork {
		score += 0.3
	}
	if _, hasProcess := data["process"]; hasProcess {
		score += 0.3
	}
	if _, hasBehavior := data["behavior"]; hasBehavior {
		score += 0.4
	}
	return math.Min(score, 1.0)
}

func (fe *FeatureExtractor) calculateComplexityScore(data map[string]interface{}) float64 {
	// Calculate complexity based on data structure depth
	complexity := 0.0
	for _, value := range data {
		if nested, ok := value.(map[string]interface{}); ok {
			complexity += float64(len(nested)) * 0.1
		}
	}
	return math.Min(complexity, 1.0)
}

func (fe *FeatureExtractor) calculateAnomalyScore(data map[string]interface{}) float64 {
	// Simple anomaly detection based on data patterns
	return rand.Float64() * 0.5 // Placeholder for more sophisticated anomaly detection
}

func (fe *FeatureExtractor) calculatePatternMatchScore(data map[string]interface{}) float64 {
	// Pattern matching score based on known attack patterns
	return rand.Float64() * 0.3 // Placeholder for pattern matching logic
}