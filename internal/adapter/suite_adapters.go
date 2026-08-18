package adapter

import (
	"database/sql"
	"os"

	"kyrecovery-server/internal/capsule"
	_ "modernc.org/sqlite"
)

// --- 1. KyBookmarks Adapter ---

// KyBookmarksRecipe returns the declarative verification recipe for KyBookmarks.
func KyBookmarksRecipe() GenericRecipe {
	return GenericRecipe{
		ServiceName:  "kybookmarks",
		IncludePaths: []string{"data", "config"},
		Dependencies: []capsule.Dependency{
			{Name: "PORT_8082", Type: "port", Required: true, Description: "KyBookmarks HTTP listener port"},
			{Name: "KY_BOOKMARKS_SECRET", Type: "env", Required: true, Description: "Session and sync encryption key"},
		},
		VerifyChecks: GenericVerifyRules{
			CheckSQLiteDatabases: true,
			ValidateJSONFiles:    true,
			RequiredFiles:        []string{"data/bookmarks.db", "config/settings.json"},
		},
	}
}

// KyBookmarksAdapter implements recovery capture and restore verification for KyBookmarks.
type KyBookmarksAdapter struct {
	*GenericAdapter
}

// NewKyBookmarksAdapter creates a new KyBookmarks adapter.
func NewKyBookmarksAdapter() *KyBookmarksAdapter {
	return &KyBookmarksAdapter{
		GenericAdapter: NewGenericAdapter(KyBookmarksRecipe()),
	}
}

// --- 2. KyNotes Adapter ---

// KyNotesRecipe returns the declarative verification recipe for KyNotes.
func KyNotesRecipe() GenericRecipe {
	return GenericRecipe{
		ServiceName:  "kynotes",
		IncludePaths: []string{"data", "keys", "config"},
		Dependencies: []capsule.Dependency{
			{Name: "PORT_8083", Type: "port", Required: true, Description: "KyNotes web and API port"},
			{Name: "KY_NOTES_KEY_DERIVATION", Type: "env", Required: true, Description: "Client-side note encryption derivation salt"},
		},
		VerifyChecks: GenericVerifyRules{
			CheckSQLiteDatabases: true,
			ValidateCertificates: true,
			ValidateJSONFiles:    true,
			RequiredFiles:        []string{"data/notes.db", "keys/jwt_notes_rsa.key", "config/kynotes.json"},
		},
	}
}

// KyNotesAdapter implements recovery capture and restore verification for KyNotes.
type KyNotesAdapter struct {
	*GenericAdapter
}

// NewKyNotesAdapter creates a new KyNotes adapter.
func NewKyNotesAdapter() *KyNotesAdapter {
	return &KyNotesAdapter{
		GenericAdapter: NewGenericAdapter(KyNotesRecipe()),
	}
}

// --- 3. KyPost Adapter ---

// KyPostRecipe returns the declarative verification recipe for KyPost.
func KyPostRecipe() GenericRecipe {
	return GenericRecipe{
		ServiceName:  "kypost",
		IncludePaths: []string{"data", "keys", "certs", "config"},
		Dependencies: []capsule.Dependency{
			{Name: "PORT_8084", Type: "port", Required: true, Description: "KyPost Web UI and SMTP submission port"},
			{Name: "PORT_8085", Type: "port", Required: true, Description: "KyPost IMAP port"},
			{Name: "KY_POST_DOMAIN", Type: "env", Required: true, Description: "Primary mail routing domain"},
		},
		VerifyChecks: GenericVerifyRules{
			CheckSQLiteDatabases: true,
			ValidateCertificates: true,
			ValidateJSONFiles:    true,
			RequiredFiles:        []string{"data/mail.db", "keys/dkim_rsa.key", "config/mail.json"},
		},
	}
}

// KyPostAdapter implements recovery capture and restore verification for KyPost.
type KyPostAdapter struct {
	*GenericAdapter
}

// NewKyPostAdapter creates a new KyPost adapter.
func NewKyPostAdapter() *KyPostAdapter {
	return &KyPostAdapter{
		GenericAdapter: NewGenericAdapter(KyPostRecipe()),
	}
}

// Helper sample database generators for tests & demo captures

func generateSampleKyBookmarksDB() ([]byte, error) {
	tmpFile, err := os.CreateTemp("", "kybookmarks-sample-*.db")
	if err != nil {
		return nil, err
	}
	tmpPath := tmpFile.Name()
	tmpFile.Close()
	defer os.Remove(tmpPath)

	dbConn, err := sql.Open("sqlite", tmpPath)
	if err != nil {
		return nil, err
	}

	schema := `
	CREATE TABLE bookmarks (
		id TEXT PRIMARY KEY,
		url TEXT NOT NULL,
		title TEXT NOT NULL,
		folder TEXT NOT NULL DEFAULT 'root',
		tags TEXT NOT NULL DEFAULT '[]',
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);
	INSERT INTO bookmarks (id, url, title, folder, tags) VALUES 
		('bm-001', 'https://kysecurity.org', 'KySecurity Suite', 'Work', '["security","auth"]'),
		('bm-002', 'https://go.dev', 'Go Programming', 'Dev', '["golang","backend"]');
	`
	if _, err := dbConn.Exec(schema); err != nil {
		dbConn.Close()
		return nil, err
	}
	dbConn.Close()

	return os.ReadFile(tmpPath)
}

func generateSampleKyNotesDB() ([]byte, error) {
	tmpFile, err := os.CreateTemp("", "kynotes-sample-*.db")
	if err != nil {
		return nil, err
	}
	tmpPath := tmpFile.Name()
	tmpFile.Close()
	defer os.Remove(tmpPath)

	dbConn, err := sql.Open("sqlite", tmpPath)
	if err != nil {
		return nil, err
	}

	schema := `
	CREATE TABLE notes (
		id TEXT PRIMARY KEY,
		title TEXT NOT NULL,
		encrypted_body BLOB NOT NULL,
		nonce BLOB NOT NULL,
		tags TEXT NOT NULL DEFAULT '[]',
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);
	INSERT INTO notes (id, title, encrypted_body, nonce) VALUES 
		('note-001', 'Disaster Recovery Runbook', X'4142434445', X'11223344556677889900aabb'),
		('note-002', 'Infrastructure Passwords', X'58595a3132', X'aabbccddeeff001122334455');
	`
	if _, err := dbConn.Exec(schema); err != nil {
		dbConn.Close()
		return nil, err
	}
	dbConn.Close()

	return os.ReadFile(tmpPath)
}

func generateSampleKyPostDB() ([]byte, error) {
	tmpFile, err := os.CreateTemp("", "kypost-sample-*.db")
	if err != nil {
		return nil, err
	}
	tmpPath := tmpFile.Name()
	tmpFile.Close()
	defer os.Remove(tmpPath)

	dbConn, err := sql.Open("sqlite", tmpPath)
	if err != nil {
		return nil, err
	}

	schema := `
	CREATE TABLE mailboxes (
		id TEXT PRIMARY KEY,
		email TEXT UNIQUE NOT NULL,
		quota_bytes INTEGER DEFAULT 10737418240,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);
	CREATE TABLE messages (
		id TEXT PRIMARY KEY,
		mailbox_id TEXT NOT NULL,
		sender TEXT NOT NULL,
		subject TEXT NOT NULL,
		body_blob BLOB NOT NULL,
		received_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (mailbox_id) REFERENCES mailboxes(id)
	);
	INSERT INTO mailboxes (id, email) VALUES ('mbx-001', 'admin@kysecurity.local');
	INSERT INTO messages (id, mailbox_id, sender, subject, body_blob) VALUES 
		('msg-001', 'mbx-001', 'alerts@recovery.local', 'Daily Verification Drill Passed', X'4d61696c20436f6e74656e74');
	`
	if _, err := dbConn.Exec(schema); err != nil {
		dbConn.Close()
		return nil, err
	}
	dbConn.Close()

	return os.ReadFile(tmpPath)
}
