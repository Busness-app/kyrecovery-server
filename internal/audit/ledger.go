package audit

import (
	"encoding/json"
	"log"
	"os"
	"strings"
	"time"
)

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

// maxActorLen bounds the actor column. It is generous for an e-mail address and
// far short of anything worth smuggling through a renderer.
const maxActorLen = 256

// sanitizeActor bounds what may be recorded as an actor. Callers are expected to
// pass a resolved identity, but the ledger is the last place to notice if one
// ever passes a caller-supplied string, so control characters and unbounded
// length stop here rather than at whatever renders the ledger later.
func sanitizeActor(actor string) string {
	actor = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, actor)
	if len(actor) > maxActorLen {
		actor = actor[:maxActorLen]
	}
	if actor == "" {
		return "unknown"
	}
	return actor
}
