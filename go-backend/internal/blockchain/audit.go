package blockchain

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

// AuditEvent represents a security event to be recorded on the blockchain
type AuditEvent struct {
	ID          string    `json:"id"`
	Timestamp   time.Time `json:"timestamp"`
	EventType   string    `json:"event_type"`
	Severity    string    `json:"severity"`
	Source      string    `json:"source"`
	Target      string    `json:"target"`
	Description string    `json:"description"`
	Metadata    map[string]interface{} `json:"metadata"`
	Hash        string    `json:"hash"`
}

// Block represents a block in the audit blockchain
type Block struct {
	Index        int64        `json:"index"`
	Timestamp    time.Time    `json:"timestamp"`
	Events       []AuditEvent `json:"events"`
	PreviousHash string       `json:"previous_hash"`
	Hash         string       `json:"hash"`
	Nonce        int64        `json:"nonce"`
}

// Blockchain represents the audit trail blockchain
type Blockchain struct {
	Chain       []Block           `json:"chain"`
	PendingEvents []AuditEvent    `json:"pending_events"`
	Difficulty  int              `json:"difficulty"`
	MiningReward float64         `json:"mining_reward"`
	mu          sync.RWMutex
}

// AuditTrail manages the blockchain audit system
type AuditTrail struct {
	blockchain *Blockchain
	mu         sync.RWMutex
}

// NewAuditTrail creates a new blockchain audit trail system
func NewAuditTrail() *AuditTrail {
	blockchain := &Blockchain{
		Chain:         []Block{},
		PendingEvents: []AuditEvent{},
		Difficulty:    2, // Adjustable mining difficulty
		MiningReward:  1.0,
	}
	
	// Create genesis block
	genesisBlock := Block{
		Index:        0,
		Timestamp:    time.Now(),
		Events:       []AuditEvent{},
		PreviousHash: "0",
		Nonce:        0,
	}
	genesisBlock.Hash = blockchain.calculateHash(genesisBlock)
	blockchain.Chain = append(blockchain.Chain, genesisBlock)
	
	auditTrail := &AuditTrail{
		blockchain: blockchain,
	}
	
	return auditTrail
}

// RecordEvent adds a new security event to the pending events
func (at *AuditTrail) RecordEvent(eventType, severity, source, target, description string, metadata map[string]interface{}) error {
	at.mu.Lock()
	defer at.mu.Unlock()
	
	event := AuditEvent{
		ID:          generateEventID(),
		Timestamp:   time.Now(),
		EventType:   eventType,
		Severity:    severity,
		Source:      source,
		Target:      target,
		Description: description,
		Metadata:    metadata,
	}
	
	// Calculate event hash
	event.Hash = at.calculateEventHash(event)
	
	at.blockchain.PendingEvents = append(at.blockchain.PendingEvents, event)
	
	// Auto-mine block if we have enough pending events
	if len(at.blockchain.PendingEvents) >= 5 {
		return at.mineBlock()
	}
	
	return nil
}

// MineBlock manually triggers block mining
func (at *AuditTrail) MineBlock() error {
	at.mu.Lock()
	defer at.mu.Unlock()
	return at.mineBlock()
}

// mineBlock creates a new block with pending events
func (at *AuditTrail) mineBlock() error {
	if len(at.blockchain.PendingEvents) == 0 {
		return fmt.Errorf("no pending events to mine")
	}
	
	previousBlock := at.blockchain.Chain[len(at.blockchain.Chain)-1]
	
	newBlock := Block{
		Index:        previousBlock.Index + 1,
		Timestamp:    time.Now(),
		Events:       make([]AuditEvent, len(at.blockchain.PendingEvents)),
		PreviousHash: previousBlock.Hash,
		Nonce:        0,
	}
	
	// Copy pending events to the new block
	copy(newBlock.Events, at.blockchain.PendingEvents)
	
	// Mine the block (proof of work)
	newBlock.Hash = at.blockchain.mineBlock(newBlock)
	
	// Add block to chain
	at.blockchain.Chain = append(at.blockchain.Chain, newBlock)
	
	// Clear pending events
	at.blockchain.PendingEvents = []AuditEvent{}
	
	return nil
}

// GetChain returns the entire blockchain
func (at *AuditTrail) GetChain() []Block {
	at.mu.RLock()
	defer at.mu.RUnlock()
	return at.blockchain.Chain
}

// GetEvents returns all events from the blockchain
func (at *AuditTrail) GetEvents() []AuditEvent {
	at.mu.RLock()
	defer at.mu.RUnlock()
	
	var allEvents []AuditEvent
	for _, block := range at.blockchain.Chain {
		allEvents = append(allEvents, block.Events...)
	}
	return allEvents
}

// GetEventsByType returns events filtered by type
func (at *AuditTrail) GetEventsByType(eventType string) []AuditEvent {
	at.mu.RLock()
	defer at.mu.RUnlock()
	
	var filteredEvents []AuditEvent
	for _, block := range at.blockchain.Chain {
		for _, event := range block.Events {
			if event.EventType == eventType {
				filteredEvents = append(filteredEvents, event)
			}
		}
	}
	return filteredEvents
}

// ValidateChain validates the integrity of the blockchain
func (at *AuditTrail) ValidateChain() bool {
	at.mu.RLock()
	defer at.mu.RUnlock()
	
	for i := 1; i < len(at.blockchain.Chain); i++ {
		currentBlock := at.blockchain.Chain[i]
		previousBlock := at.blockchain.Chain[i-1]
		
		// Validate current block hash
		if currentBlock.Hash != at.blockchain.calculateHash(currentBlock) {
			return false
		}
		
		// Validate previous hash link
		if currentBlock.PreviousHash != previousBlock.Hash {
			return false
		}
	}
	return true
}

// GetStats returns blockchain statistics
func (at *AuditTrail) GetStats() map[string]interface{} {
	at.mu.RLock()
	defer at.mu.RUnlock()
	
	totalEvents := 0
	for _, block := range at.blockchain.Chain {
		totalEvents += len(block.Events)
	}
	
	return map[string]interface{}{
		"total_blocks":     len(at.blockchain.Chain),
		"total_events":     totalEvents,
		"pending_events":   len(at.blockchain.PendingEvents),
		"chain_valid":      at.ValidateChain(),
		"difficulty":       at.blockchain.Difficulty,
		"latest_block_time": at.blockchain.Chain[len(at.blockchain.Chain)-1].Timestamp,
	}
}

// calculateHash calculates the hash of a block
func (bc *Blockchain) calculateHash(block Block) string {
	data := fmt.Sprintf("%d%s%s%d", block.Index, block.Timestamp.String(), block.PreviousHash, block.Nonce)
	
	// Include events in hash calculation
	for _, event := range block.Events {
		data += event.Hash
	}
	
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}

// mineBlock performs proof of work mining
func (bc *Blockchain) mineBlock(block Block) string {
	target := fmt.Sprintf("%0*d", bc.Difficulty, 0)
	
	for {
		hash := bc.calculateHash(block)
		if hash[:bc.Difficulty] == target {
			return hash
		}
		block.Nonce++
	}
}

// calculateEventHash calculates the hash of an audit event
func (at *AuditTrail) calculateEventHash(event AuditEvent) string {
	data := fmt.Sprintf("%s%s%s%s%s%s%s", 
		event.ID, 
		event.Timestamp.String(), 
		event.EventType, 
		event.Severity, 
		event.Source, 
		event.Target, 
		event.Description)
	
	// Include metadata in hash
	if metadataBytes, err := json.Marshal(event.Metadata); err == nil {
		data += string(metadataBytes)
	}
	
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}

// generateEventID generates a unique event ID
func generateEventID() string {
	timestamp := time.Now().UnixNano()
	hash := sha256.Sum256([]byte(fmt.Sprintf("%d", timestamp)))
	return hex.EncodeToString(hash[:8]) // Use first 8 bytes for shorter ID
}

// ExportChain exports the blockchain to JSON
func (at *AuditTrail) ExportChain() ([]byte, error) {
	at.mu.RLock()
	defer at.mu.RUnlock()
	return json.MarshalIndent(at.blockchain, "", "  ")
}

// ImportChain imports a blockchain from JSON
func (at *AuditTrail) ImportChain(data []byte) error {
	at.mu.Lock()
	defer at.mu.Unlock()
	
	var importedBlockchain Blockchain
	if err := json.Unmarshal(data, &importedBlockchain); err != nil {
		return err
	}
	
	// Validate imported chain
	tempAuditTrail := &AuditTrail{blockchain: &importedBlockchain}
	if !tempAuditTrail.ValidateChain() {
		return fmt.Errorf("imported blockchain is invalid")
	}
	
	at.blockchain = &importedBlockchain
	return nil
}