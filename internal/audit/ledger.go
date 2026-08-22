package audit

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"sync"
	"time"

	"kyrecovery-server/internal/db"
	"kyrecovery-server/internal/secrets"
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

// Log returns the shared structured logger.
func Log() *Logger { return defaultLogger }

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
//
// Events are chained with HMAC-SHA256 under a key held outside SQLite (see
// internal/secrets), so an attacker who can write to the database cannot edit an
// event and recompute the chain. That covers a stolen or replicated database
// file, and SQL-level access. It does not cover an attacker who holds the server
// key or the data directory — they can forge the chain, or remove the migration
// marker and have a forged chain re-keyed on restart. For a guarantee that
// survives full host compromise, anchor the chain head somewhere KyRecovery
// cannot write.
type Ledger struct {
	mu   sync.Mutex
	db   *db.DB
	key  []byte
	keys *secrets.Keyring
}

// NewLedger initializes an audit ledger keyed by the database's server keyring.
// On the first open after an upgrade it re-authenticates any pre-existing chain
// under the ledger key; afterwards unkeyed event hashes are always rejected.
func NewLedger(database *db.DB) *Ledger {
	l := &Ledger{db: database}
	if database == nil {
		return l
	}
	l.keys = database.Keyring()
	l.key = l.keys.LedgerKey()
	if err := l.rekeyLegacyChain(context.Background()); err != nil {
		defaultLogger.Error("ledger_rekey", "system", "audit_events", "failed re-keying the existing audit chain", err)
	}
	return l
}

// rekeyLegacyChain rewrites the chain linkage of events written before the
// ledger was keyed. The chain must verify under the unkeyed algorithm first, so
// a chain that was already broken is never blessed. This runs once: the outcome
// is recorded outside SQLite, beyond the reach of a database-only attacker.
func (l *Ledger) rekeyLegacyChain(ctx context.Context) error {
	if l.keys == nil || l.keys.LedgerKeyed() {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	events, err := l.db.ListAuditEvents(ctx, 100000)
	if err != nil {
		return err
	}
	for i, j := 0, len(events)-1; i < j; i, j = i+1, j-1 {
		events[i], events[j] = events[j], events[i]
	}

	// Pass one: the stored chain must be self-consistent under the unkeyed
	// algorithm (or already keyed) before anything is rewritten.
	prevStored := GenesisHash
	rekeyed := 0
	for _, ev := range events {
		if ev.PrevHash != prevStored {
			return fmt.Errorf("audit chain is broken at sequence %d; refusing to re-key it", ev.SequenceNum)
		}
		legacy := CalculateEventHash(ev.SequenceNum, ev.PrevHash, ev.Action, ev.Actor, ev.TargetID, ev.DetailsJSON, ev.CreatedAt)
		keyed := l.eventHash(ev.SequenceNum, ev.PrevHash, ev.Action, ev.Actor, ev.TargetID, ev.DetailsJSON, ev.CreatedAt)
		switch ev.EventHash {
		case keyed:
		case legacy:
			rekeyed++
		default:
			return fmt.Errorf("audit event %d does not match its recorded hash; refusing to re-key it", ev.SequenceNum)
		}
		prevStored = ev.EventHash
	}

	// Pass two: relink the whole chain under the ledger key.
	prev := GenesisHash
	for _, ev := range events {
		h := l.eventHash(ev.SequenceNum, prev, ev.Action, ev.Actor, ev.TargetID, ev.DetailsJSON, ev.CreatedAt)
		if err := l.db.UpdateAuditEventHashes(ctx, ev.SequenceNum, prev, h); err != nil {
			return err
		}
		prev = h
	}

	if rekeyed > 0 {
		defaultLogger.Info("ledger_rekey", "system", "audit_events", "REKEYED",
			fmt.Sprintf("%d pre-existing audit events are now authenticated with the server ledger key", rekeyed))
	}
	return l.keys.MarkLedgerKeyed()
}

// CalculateEventHash computes the unkeyed SHA256 of the event tuple.
//
// Deprecated: retained to verify chains written before the ledger was keyed.
// New events use Ledger.eventHash.
func CalculateEventHash(seq int64, prevHash, action, actor, targetID, detailsJSON string, createdAt time.Time) string {
	h := sha256.New()
	h.Write(eventTuple(seq, prevHash, action, actor, targetID, detailsJSON, createdAt))
	return hex.EncodeToString(h.Sum(nil))
}

func eventTuple(seq int64, prevHash, action, actor, targetID, detailsJSON string, createdAt time.Time) []byte {
	detailsHash := sha256.Sum256([]byte(detailsJSON))
	detailsHex := hex.EncodeToString(detailsHash[:])

	timeStr := createdAt.UTC().Format(time.RFC3339Nano)
	return []byte(fmt.Sprintf("%d|%s|%s|%s|%s|%s|%s", seq, prevHash, action, actor, targetID, detailsHex, timeStr))
}

// eventHash authenticates an event under the server ledger key.
func (l *Ledger) eventHash(seq int64, prevHash, action, actor, targetID, detailsJSON string, createdAt time.Time) string {
	if len(l.key) == 0 {
		return CalculateEventHash(seq, prevHash, action, actor, targetID, detailsJSON, createdAt)
	}
	mac := hmac.New(sha256.New, l.key)
	mac.Write(eventTuple(seq, prevHash, action, actor, targetID, detailsJSON, createdAt))
	return hex.EncodeToString(mac.Sum(nil))
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
	eventHash := l.eventHash(seq, prevHash, action, actor, targetID, detailsJSON, now)

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

// ChainStatus reports the outcome of an audit chain verification.
type ChainStatus struct {
	Valid    bool   `json:"valid"`
	Count    int64  `json:"count"`
	LastHash string `json:"last_hash"`
}

// VerifyChain verifies the integrity of the audit chain from sequence 1 to the end.
func (l *Ledger) VerifyChain(ctx context.Context) (ChainStatus, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	events, err := l.db.ListAuditEvents(ctx, 100000)
	if err != nil {
		return ChainStatus{}, err
	}
	if len(events) == 0 {
		return ChainStatus{Valid: true, LastHash: GenesisHash}, nil
	}

	// ListAuditEvents returns descending, reverse to ascending for chain verification
	for i, j := 0, len(events)-1; i < j; i, j = i+1, j-1 {
		events[i], events[j] = events[j], events[i]
	}

	status := ChainStatus{}
	expectedPrev := GenesisHash
	for i, ev := range events {
		status.Count = ev.SequenceNum
		status.LastHash = ev.EventHash

		expectedSeq := int64(i + 1)
		if ev.SequenceNum != expectedSeq {
			return status, fmt.Errorf("sequence gap at index %d: expected %d, got %d", i, expectedSeq, ev.SequenceNum)
		}
		if ev.PrevHash != expectedPrev {
			return status, fmt.Errorf("hash chain broken at sequence %d: prev_hash mismatch", ev.SequenceNum)
		}

		computed := l.eventHash(ev.SequenceNum, ev.PrevHash, ev.Action, ev.Actor, ev.TargetID, ev.DetailsJSON, ev.CreatedAt)
		if !hmac.Equal([]byte(computed), []byte(ev.EventHash)) {
			return status, fmt.Errorf("event hash mismatch at sequence %d", ev.SequenceNum)
		}

		expectedPrev = ev.EventHash
	}

	status.Valid = true
	status.Count = int64(len(events))
	status.LastHash = expectedPrev
	return status, nil
}
