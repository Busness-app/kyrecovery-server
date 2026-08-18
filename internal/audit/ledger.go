package audit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"sync"
	"time"

	"kyrecovery-server/internal/db"
)

const GenesisHash = "0000000000000000000000000000000000000000000000000000000000000000"

// Logger provides privacy-safe, structured JSON logging to stdout/stderr.
type Logger struct {
	stdLogger *log.Logger
	errLogger *log.Logger
}

var (
	defaultLogger = NewLogger()
)

// LogEntry is the schema for structured log emissions.
type LogEntry struct {
	Timestamp string `json:"timestamp"`
	Level     string `json:"level"`
	Action    string `json:"action"`
	Actor     string `json:"actor,omitempty"`
	TargetID  string `json:"target_id,omitempty"`
	Status    string `json:"status,omitempty"`
	Message   string `json:"message,omitempty"`
	Duration  string `json:"duration,omitempty"`
	Error     string `json:"error,omitempty"`
}

// NewLogger creates a structured logger.
func NewLogger() *Logger {
	return &Logger{
		stdLogger: log.New(os.Stdout, "", 0),
		errLogger: log.New(os.Stderr, "", 0),
	}
}

func (l *Logger) Info(action, actor, targetID, status, message string) {
	entry := LogEntry{
		Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
		Level:     "INFO",
		Action:    action,
		Actor:     actor,
		TargetID:  targetID,
		Status:    status,
		Message:   message,
	}
	b, _ := json.Marshal(entry)
	l.stdLogger.Println(string(b))
}

func (l *Logger) Error(action, actor, targetID, message string, err error) {
	errStr := ""
	if err != nil {
		errStr = err.Error()
	}
	entry := LogEntry{
		Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
		Level:     "ERROR",
		Action:    action,
		Actor:     actor,
		TargetID:  targetID,
		Message:   message,
		Error:     errStr,
	}
	b, _ := json.Marshal(entry)
	l.errLogger.Println(string(b))
}

// Ledger manages the append-only hash-chained audit trail.
type Ledger struct {
	mu sync.Mutex
	db *db.DB
}

// NewLedger initializes an audit ledger.
func NewLedger(database *db.DB) *Ledger {
	return &Ledger{
		db: database,
	}
}

// CalculateEventHash computes the cryptographic SHA256 of the event tuple.
func CalculateEventHash(seq int64, prevHash, action, actor, targetID, detailsJSON string, createdAt time.Time) string {
	detailsHash := sha256.Sum256([]byte(detailsJSON))
	detailsHex := hex.EncodeToString(detailsHash[:])

	timeStr := createdAt.UTC().Format(time.RFC3339Nano)
	raw := fmt.Sprintf("%d|%s|%s|%s|%s|%s|%s", seq, prevHash, action, actor, targetID, detailsHex, timeStr)
	h := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(h[:])
}

// Record appends a new verified event to the tamper-evident chain and emits structured log.
func (l *Ledger) Record(ctx context.Context, action, actor, targetID string, details map[string]interface{}) (*db.AuditRecord, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	last, err := l.db.GetLastAuditEvent(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed fetching last audit event: %w", err)
	}

	var seq int64 = 1
	prevHash := GenesisHash
	if last != nil {
		seq = last.SequenceNum + 1
		prevHash = last.EventHash
	}

	detailsBytes, err := json.Marshal(details)
	if err != nil {
		detailsBytes = []byte("{}")
	}
	detailsJSON := string(detailsBytes)

	now := time.Now().UTC()
	eventHash := CalculateEventHash(seq, prevHash, action, actor, targetID, detailsJSON, now)

	record := db.AuditRecord{
		SequenceNum: seq,
		PrevHash:    prevHash,
		Action:      action,
		Actor:       actor,
		TargetID:    targetID,
		DetailsJSON: detailsJSON,
		EventHash:   eventHash,
		CreatedAt:   now,
	}

	if err := l.db.InsertAuditEvent(ctx, record); err != nil {
		defaultLogger.Error(action, actor, targetID, "failed to insert audit event", err)
		return nil, fmt.Errorf("failed to persist audit record: %w", err)
	}

	defaultLogger.Info(action, actor, targetID, "AUDIT_RECORDED", fmt.Sprintf("seq=%d hash=%s", seq, eventHash[:8]))
	return &record, nil
}

// VerifyChain verifies the integrity of the audit chain from sequence 1 to the end.
func (l *Ledger) VerifyChain(ctx context.Context) (bool, int64, string, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	events, err := l.db.ListAuditEvents(ctx, 100000)
	if err != nil {
		return false, 0, "", err
	}
	if len(events) == 0 {
		return true, 0, GenesisHash, nil
	}

	// ListAuditEvents returns descending, reverse to ascending for chain verification
	for i, j := 0, len(events)-1; i < j; i, j = i+1, j-1 {
		events[i], events[j] = events[j], events[i]
	}

	expectedPrev := GenesisHash
	for i, ev := range events {
		expectedSeq := int64(i + 1)
		if ev.SequenceNum != expectedSeq {
			return false, ev.SequenceNum, ev.EventHash, fmt.Errorf("sequence gap at index %d: expected %d, got %d", i, expectedSeq, ev.SequenceNum)
		}
		if ev.PrevHash != expectedPrev {
			return false, ev.SequenceNum, ev.EventHash, fmt.Errorf("hash chain broken at sequence %d: prev_hash mismatch", ev.SequenceNum)
		}

		computedHash := CalculateEventHash(ev.SequenceNum, ev.PrevHash, ev.Action, ev.Actor, ev.TargetID, ev.DetailsJSON, ev.CreatedAt)
		if computedHash != ev.EventHash {
			return false, ev.SequenceNum, ev.EventHash, fmt.Errorf("event hash mismatch at sequence %d: recorded=%s computed=%s", ev.SequenceNum, ev.EventHash, computedHash)
		}

		expectedPrev = ev.EventHash
	}

	return true, int64(len(events)), expectedPrev, nil
}
