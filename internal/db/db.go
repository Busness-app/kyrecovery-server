package db

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"

	"github.com/Busness-app/kyrecovery-server/internal/secrets"
)

// CapsuleRecord stores metadata for a stored capsule.
type CapsuleRecord struct {
	ID          string    `json:"id"`
	ServiceName string    `json:"service_name"`
	FilePath    string    `json:"-"`
	SizeBytes   int64     `json:"size_bytes"`
	PayloadHash string    `json:"payload_hash"`
	Threshold   int       `json:"threshold"`
	TotalShares int       `json:"total_shares"`
	Status      string    `json:"status"`
	CreatedAt   time.Time `json:"created_at"`
}

// CustodianRecord represents a designated recovery custodian.
type CustodianRecord struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Email       string    `json:"email"`
	Fingerprint string    `json:"fingerprint"`
	CreatedAt   time.Time `json:"created_at"`
}

// DrillRecord represents the outcome of an ephemeral restore drill.
type DrillRecord struct {
	ID           string    `json:"id"`
	CapsuleID    string    `json:"capsule_id"`
	ServiceName  string    `json:"service_name"`
	Status       string    `json:"status"` // "passed", "failed"
	DurationMs   int64     `json:"duration_ms"`
	MissingDeps  []string  `json:"missing_deps"`
	ErrorMessage string    `json:"error_message"`
	DetailsJSON  string    `json:"details_json"`
	StartedAt    time.Time `json:"started_at"`
	CompletedAt  time.Time `json:"completed_at"`
}

// AuditRecord represents a tamper-evident audit event.
type AuditRecord struct {
	ID          int64     `json:"id"`
	SequenceNum int64     `json:"sequence_num"`
	PrevHash    string    `json:"prev_hash"`
	Action      string    `json:"action"`
	Actor       string    `json:"actor"`
	TargetID    string    `json:"target_id"`
	DetailsJSON string    `json:"details_json"`
	EventHash   string    `json:"event_hash"`
	CreatedAt   time.Time `json:"created_at"`
}

// PairedAppRecord represents a connected KySecurity or Business.app service.
// APIToken and PairingCode are credentials, so they never serialise by default:
// the pairing code is returned only by the admin route that generates it, and the
// token only by the claim that mints it.
type PairedAppRecord struct {
	ID           string     `json:"id"`
	ServiceName  string     `json:"service_name"`
	AppName      string     `json:"app_name"`
	APIToken     string     `json:"-"`
	PairingCode  string     `json:"-"`
	Status       string     `json:"status"` // "pending", "paired", "revoked"
	ExpiresAt    time.Time  `json:"expires_at"`
	PairedAt     *time.Time `json:"paired_at,omitempty"`
	LastBackupAt *time.Time `json:"last_backup_at,omitempty"`
	CreatedAt    time.Time  `json:"created_at"`
}

// RecoveryKeyRecord is the suite recovery public key this store hands to products and pins
// deposits against. There is exactly one row; the private half never existed here.
type RecoveryKeyRecord struct {
	KeyID       string    `json:"key_id"`
	PublicKey   []byte    `json:"-"`
	Threshold   int       `json:"threshold"`
	TotalShares int       `json:"total_shares"`
	ImportedBy  string    `json:"imported_by"`
	ImportedAt  time.Time `json:"imported_at"`
}

var ErrRecoveryKeyExists = errors.New("a recovery key is already imported")

// UserRecord represents a local user account.
type UserRecord struct {
	ID           string    `json:"id"`
	Username     string    `json:"username"`
	PasswordHash string    `json:"password_hash"`
	Salt         string    `json:"salt"`
	Email        string    `json:"email"`
	Name         string    `json:"name"`
	Role         string    `json:"role"`
	CreatedAt    time.Time `json:"created_at"`
}

// SessionRecord represents an authenticated user session. ID is the bearer
// credential the session cookie carries, so it is never serialised into a response.
type SessionRecord struct {
	ID        string    `json:"-"`
	UserID    string    `json:"user_id"`
	Email     string    `json:"email"`
	Name      string    `json:"name"`
	Role      string    `json:"role"`
	ExpiresAt time.Time `json:"expires_at"`
	CreatedAt time.Time `json:"created_at"`
}

// ReplicationTargetRecord defines an offsite backup target (S3, Cloudflare R2, MinIO, Local).
type ReplicationTargetRecord struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	Type       string     `json:"type"` // "s3", "local"
	Endpoint   string     `json:"endpoint"`
	Bucket     string     `json:"bucket"`
	Region     string     `json:"region"`
	AccessKey  string     `json:"access_key"`
	SecretKey  string     `json:"secret_key,omitempty"`
	Prefix     string     `json:"prefix"`
	AutoSync   bool       `json:"auto_sync"`
	Status     string     `json:"status"` // "active", "disabled", "error"
	LastSyncAt *time.Time `json:"last_sync_at,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
}

// ReplicationLogRecord tracks an individual capsule transfer to a remote target.
type ReplicationLogRecord struct {
	ID               int64     `json:"id"`
	TargetID         string    `json:"target_id"`
	CapsuleID        string    `json:"capsule_id"`
	BytesTransferred int64     `json:"bytes_transferred"`
	DurationMs       int64     `json:"duration_ms"`
	Status           string    `json:"status"` // "success", "failed"
	ErrorMessage     string    `json:"error_message,omitempty"`
	CreatedAt        time.Time `json:"created_at"`
}

// DB wraps the SQLite database handle.
type DB struct {
	conn *sql.DB
	keys *secrets.Keyring
}

// Open initializes or connects to SQLite at dbPath.
func Open(dbPath string) (*DB, error) {
	if dbPath != ":memory:" {
		dir := filepath.Dir(dbPath)
		if err := os.MkdirAll(dir, 0700); err != nil {
			return nil, fmt.Errorf("failed to create database directory: %w", err)
		}
	}

	dsn := fmt.Sprintf("%s?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(ON)", dbPath)
	conn, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to open sqlite database: %w", err)
	}

	conn.SetMaxOpenConns(1) // SQLite single-writer safety

	// Credentials are sealed with a key held outside the database, so a stolen
	// copy of the database file is not a copy of the offsite storage credentials.
	keyDir := ""
	if dbPath != ":memory:" {
		keyDir = filepath.Dir(dbPath)
	}
	keys, err := secrets.Load(keyDir)
	if err != nil {
		conn.Close()
		return nil, err
	}

	database := &DB{conn: conn, keys: keys}
	if err := database.migrate(); err != nil {
		conn.Close()
		return nil, fmt.Errorf("migration failed: %w", err)
	}

	return database, nil
}

// Keyring returns the server keyring protecting at-rest secrets.
func (d *DB) Keyring() *secrets.Keyring { return d.keys }

// Close closes the database connection.
func (d *DB) Close() error {
	return d.conn.Close()
}

func (d *DB) migrate() error {
	schema := `
	CREATE TABLE IF NOT EXISTS users (
		id TEXT PRIMARY KEY,
		username TEXT NOT NULL UNIQUE,
		password_hash TEXT NOT NULL,
		salt TEXT NOT NULL,
		email TEXT NOT NULL,
		name TEXT NOT NULL,
		role TEXT NOT NULL DEFAULT 'operator',
		created_at DATETIME NOT NULL
	);

	CREATE TABLE IF NOT EXISTS system_settings (
		key TEXT PRIMARY KEY,
		value TEXT NOT NULL,
		updated_at DATETIME NOT NULL
	);

	CREATE TABLE IF NOT EXISTS capsules (
		id TEXT PRIMARY KEY,
		service_name TEXT NOT NULL,
		file_path TEXT NOT NULL,
		size_bytes INTEGER NOT NULL,
		payload_hash TEXT NOT NULL,
		threshold INTEGER NOT NULL,
		total_shares INTEGER NOT NULL,
		status TEXT NOT NULL DEFAULT 'active',
		created_at DATETIME NOT NULL
	);

	CREATE TABLE IF NOT EXISTS custodians (
		id TEXT PRIMARY KEY,
		name TEXT NOT NULL,
		email TEXT NOT NULL,
		fingerprint TEXT NOT NULL,
		created_at DATETIME NOT NULL
	);

	CREATE TABLE IF NOT EXISTS drills (
		id TEXT PRIMARY KEY,
		capsule_id TEXT NOT NULL,
		service_name TEXT NOT NULL,
		status TEXT NOT NULL,
		duration_ms INTEGER NOT NULL,
		missing_deps TEXT NOT NULL DEFAULT '[]',
		error_message TEXT NOT NULL DEFAULT '',
		details_json TEXT NOT NULL DEFAULT '{}',
		started_at DATETIME NOT NULL,
		completed_at DATETIME NOT NULL,
		FOREIGN KEY (capsule_id) REFERENCES capsules(id) ON DELETE CASCADE
	);

	CREATE TABLE IF NOT EXISTS audit_events (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		sequence_num INTEGER NOT NULL UNIQUE,
		prev_hash TEXT NOT NULL,
		action TEXT NOT NULL,
		actor TEXT NOT NULL,
		target_id TEXT NOT NULL,
		details_json TEXT NOT NULL,
		event_hash TEXT NOT NULL,
		created_at DATETIME NOT NULL
	);

	CREATE TABLE IF NOT EXISTS paired_apps (
		id TEXT PRIMARY KEY,
		service_name TEXT NOT NULL,
		app_name TEXT NOT NULL,
		api_token TEXT NOT NULL UNIQUE,
		pairing_code TEXT NOT NULL,
		status TEXT NOT NULL DEFAULT 'pending',
		expires_at DATETIME NOT NULL,
		paired_at DATETIME,
		last_backup_at DATETIME,
		created_at DATETIME NOT NULL
	);

	CREATE TABLE IF NOT EXISTS sessions (
		id TEXT PRIMARY KEY,
		user_id TEXT NOT NULL,
		email TEXT NOT NULL,
		name TEXT NOT NULL,
		role TEXT NOT NULL DEFAULT 'operator',
		expires_at DATETIME NOT NULL,
		created_at DATETIME NOT NULL
	);

	CREATE TABLE IF NOT EXISTS replication_targets (
		id TEXT PRIMARY KEY,
		name TEXT NOT NULL,
		type TEXT NOT NULL,
		endpoint TEXT NOT NULL,
		bucket TEXT NOT NULL,
		region TEXT NOT NULL DEFAULT 'us-east-1',
		access_key TEXT NOT NULL,
		secret_key TEXT NOT NULL,
		prefix TEXT NOT NULL DEFAULT 'capsules/',
		auto_sync INTEGER NOT NULL DEFAULT 1,
		status TEXT NOT NULL DEFAULT 'active',
		last_sync_at DATETIME,
		created_at DATETIME NOT NULL
	);

	CREATE TABLE IF NOT EXISTS replication_logs (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		target_id TEXT NOT NULL,
		capsule_id TEXT NOT NULL,
		bytes_transferred INTEGER NOT NULL,
		duration_ms INTEGER NOT NULL,
		status TEXT NOT NULL,
		error_message TEXT NOT NULL DEFAULT '',
		created_at DATETIME NOT NULL,
		FOREIGN KEY (target_id) REFERENCES replication_targets(id) ON DELETE CASCADE
	);

	CREATE TABLE IF NOT EXISTS recovery_key (
		singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
		key_id TEXT NOT NULL,
		public_key BLOB NOT NULL,
		threshold INTEGER NOT NULL,
		total_shares INTEGER NOT NULL,
		imported_by TEXT NOT NULL,
		imported_at DATETIME NOT NULL
	);

	CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
	CREATE INDEX IF NOT EXISTS idx_capsules_service ON capsules(service_name);
	CREATE INDEX IF NOT EXISTS idx_drills_capsule ON drills(capsule_id);
	CREATE INDEX IF NOT EXISTS idx_audit_seq ON audit_events(sequence_num);
	CREATE INDEX IF NOT EXISTS idx_paired_code ON paired_apps(pairing_code);
	CREATE INDEX IF NOT EXISTS idx_paired_token ON paired_apps(api_token);
	CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
	CREATE INDEX IF NOT EXISTS idx_repl_logs_target ON replication_logs(target_id);
	`

	_, err := d.conn.Exec(schema)
	return err
}

// InsertCapsule saves a new capsule record.
func (d *DB) InsertCapsule(ctx context.Context, c CapsuleRecord) error {
	q := `INSERT INTO capsules (id, service_name, file_path, size_bytes, payload_hash, threshold, total_shares, status, created_at)
	      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
	_, err := d.conn.ExecContext(ctx, q, c.ID, c.ServiceName, c.FilePath, c.SizeBytes, c.PayloadHash, c.Threshold, c.TotalShares, c.Status, c.CreatedAt.UTC())
	return err
}

// GetCapsule retrieves a capsule by ID.
func (d *DB) GetCapsule(ctx context.Context, id string) (*CapsuleRecord, error) {
	q := `SELECT id, service_name, file_path, size_bytes, payload_hash, threshold, total_shares, status, created_at FROM capsules WHERE id = ?`
	row := d.conn.QueryRowContext(ctx, q, id)
	var c CapsuleRecord
	err := row.Scan(&c.ID, &c.ServiceName, &c.FilePath, &c.SizeBytes, &c.PayloadHash, &c.Threshold, &c.TotalShares, &c.Status, &c.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &c, nil
}

// ListCapsules returns all active capsules.
func (d *DB) ListCapsules(ctx context.Context) ([]CapsuleRecord, error) {
	q := `SELECT id, service_name, file_path, size_bytes, payload_hash, threshold, total_shares, status, created_at FROM capsules ORDER BY created_at DESC`
	rows, err := d.conn.QueryContext(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []CapsuleRecord
	for rows.Next() {
		var c CapsuleRecord
		if err := rows.Scan(&c.ID, &c.ServiceName, &c.FilePath, &c.SizeBytes, &c.PayloadHash, &c.Threshold, &c.TotalShares, &c.Status, &c.CreatedAt); err != nil {
			return nil, err
		}
		list = append(list, c)
	}
	return list, rows.Err()
}

// InsertCustodian adds a custodian.
func (d *DB) InsertCustodian(ctx context.Context, c CustodianRecord) error {
	q := `INSERT INTO custodians (id, name, email, fingerprint, created_at) VALUES (?, ?, ?, ?, ?)`
	_, err := d.conn.ExecContext(ctx, q, c.ID, c.Name, c.Email, c.Fingerprint, c.CreatedAt.UTC())
	return err
}

// ListCustodians returns all registered custodians.
func (d *DB) ListCustodians(ctx context.Context) ([]CustodianRecord, error) {
	q := `SELECT id, name, email, fingerprint, created_at FROM custodians ORDER BY name ASC`
	rows, err := d.conn.QueryContext(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []CustodianRecord
	for rows.Next() {
		var c CustodianRecord
		if err := rows.Scan(&c.ID, &c.Name, &c.Email, &c.Fingerprint, &c.CreatedAt); err != nil {
			return nil, err
		}
		list = append(list, c)
	}
	return list, rows.Err()
}

// InsertDrill records a drill execution.
func (d *DB) InsertDrill(ctx context.Context, dr DrillRecord) error {
	depsJSON, err := json.Marshal(dr.MissingDeps)
	if err != nil {
		depsJSON = []byte("[]")
	}

	q := `INSERT INTO drills (id, capsule_id, service_name, status, duration_ms, missing_deps, error_message, details_json, started_at, completed_at)
	      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
	_, err = d.conn.ExecContext(ctx, q, dr.ID, dr.CapsuleID, dr.ServiceName, dr.Status, dr.DurationMs, string(depsJSON), dr.ErrorMessage, dr.DetailsJSON, dr.StartedAt.UTC(), dr.CompletedAt.UTC())
	return err
}

// ListDrills returns drill history.
func (d *DB) ListDrills(ctx context.Context, limit int) ([]DrillRecord, error) {
	if limit <= 0 {
		limit = 50
	}
	q := `SELECT id, capsule_id, service_name, status, duration_ms, missing_deps, error_message, details_json, started_at, completed_at FROM drills ORDER BY started_at DESC LIMIT ?`
	rows, err := d.conn.QueryContext(ctx, q, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []DrillRecord
	for rows.Next() {
		var (
			dr       DrillRecord
			depsJSON string
		)
		if err := rows.Scan(&dr.ID, &dr.CapsuleID, &dr.ServiceName, &dr.Status, &dr.DurationMs, &depsJSON, &dr.ErrorMessage, &dr.DetailsJSON, &dr.StartedAt, &dr.CompletedAt); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(depsJSON), &dr.MissingDeps)
		list = append(list, dr)
	}
	return list, rows.Err()
}

// GetLastDrill retrieves the most recent drill.
func (d *DB) GetLastDrill(ctx context.Context) (*DrillRecord, error) {
	list, err := d.ListDrills(ctx, 1)
	if err != nil {
		return nil, err
	}
	if len(list) == 0 {
		return nil, nil
	}
	return &list[0], nil
}

// GetLastAuditEvent returns the latest audit record or nil if empty.
func (d *DB) GetLastAuditEvent(ctx context.Context) (*AuditRecord, error) {
	q := `SELECT id, sequence_num, prev_hash, action, actor, target_id, details_json, event_hash, created_at FROM audit_events ORDER BY sequence_num DESC LIMIT 1`
	row := d.conn.QueryRowContext(ctx, q)
	var ar AuditRecord
	err := row.Scan(&ar.ID, &ar.SequenceNum, &ar.PrevHash, &ar.Action, &ar.Actor, &ar.TargetID, &ar.DetailsJSON, &ar.EventHash, &ar.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &ar, nil
}

// InsertAuditEvent inserts a new chained audit event.
func (d *DB) InsertAuditEvent(ctx context.Context, ar AuditRecord) error {
	q := `INSERT INTO audit_events (sequence_num, prev_hash, action, actor, target_id, details_json, event_hash, created_at)
	      VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
	_, err := d.conn.ExecContext(ctx, q, ar.SequenceNum, ar.PrevHash, ar.Action, ar.Actor, ar.TargetID, ar.DetailsJSON, ar.EventHash, ar.CreatedAt.UTC())
	return err
}

// UpdateAuditEventHashes rewrites the chain linkage of an existing audit event.
// It changes no event content: it is used only to re-authenticate an existing
// chain under the server ledger key.
func (d *DB) UpdateAuditEventHashes(ctx context.Context, seq int64, prevHash, eventHash string) error {
	q := `UPDATE audit_events SET prev_hash = ?, event_hash = ? WHERE sequence_num = ?`
	_, err := d.conn.ExecContext(ctx, q, prevHash, eventHash, seq)
	return err
}

// ListAuditEvents returns audit events in chronological or reverse-chronological order.
func (d *DB) ListAuditEvents(ctx context.Context, limit int) ([]AuditRecord, error) {
	if limit <= 0 {
		limit = 100
	}
	q := `SELECT id, sequence_num, prev_hash, action, actor, target_id, details_json, event_hash, created_at FROM audit_events ORDER BY sequence_num DESC LIMIT ?`
	rows, err := d.conn.QueryContext(ctx, q, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []AuditRecord
	for rows.Next() {
		var ar AuditRecord
		if err := rows.Scan(&ar.ID, &ar.SequenceNum, &ar.PrevHash, &ar.Action, &ar.Actor, &ar.TargetID, &ar.DetailsJSON, &ar.EventHash, &ar.CreatedAt); err != nil {
			return nil, err
		}
		list = append(list, ar)
	}
	return list, rows.Err()
}

// InsertPairedApp stores a pending pairing code record.
func (d *DB) InsertPairedApp(ctx context.Context, app PairedAppRecord) error {
	q := `INSERT INTO paired_apps (id, service_name, app_name, api_token, pairing_code, status, expires_at, created_at)
	      VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
	_, err := d.conn.ExecContext(ctx, q, app.ID, app.ServiceName, app.AppName, app.APIToken, app.PairingCode, app.Status, app.ExpiresAt.UTC(), app.CreatedAt.UTC())
	return err
}

// GetPairedAppByCode finds a pending pairing code.
func (d *DB) GetPairedAppByCode(ctx context.Context, code string) (*PairedAppRecord, error) {
	q := `SELECT id, service_name, app_name, api_token, pairing_code, status, expires_at, paired_at, last_backup_at, created_at
	      FROM paired_apps WHERE pairing_code = ?`
	row := d.conn.QueryRowContext(ctx, q, code)
	var a PairedAppRecord
	err := row.Scan(&a.ID, &a.ServiceName, &a.AppName, &a.APIToken, &a.PairingCode, &a.Status, &a.ExpiresAt, &a.PairedAt, &a.LastBackupAt, &a.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &a, nil
}

// GetPairedAppByToken finds an active paired app by its API bearer token.
func (d *DB) GetPairedAppByToken(ctx context.Context, token string) (*PairedAppRecord, error) {
	q := `SELECT id, service_name, app_name, api_token, pairing_code, status, expires_at, paired_at, last_backup_at, created_at
	      FROM paired_apps WHERE api_token = ? AND status = 'paired'`
	row := d.conn.QueryRowContext(ctx, q, token)
	var a PairedAppRecord
	err := row.Scan(&a.ID, &a.ServiceName, &a.AppName, &a.APIToken, &a.PairingCode, &a.Status, &a.ExpiresAt, &a.PairedAt, &a.LastBackupAt, &a.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &a, nil
}

// ClaimPairingCode consumes a pairing code and marks it paired with specific app name/service.
func (d *DB) ClaimPairingCode(ctx context.Context, code, serviceName, appName string) (*PairedAppRecord, error) {
	app, err := d.GetPairedAppByCode(ctx, code)
	if err != nil {
		return nil, err
	}
	if app == nil {
		return nil, errors.New("invalid or expired pairing code")
	}
	if app.Status != "pending" {
		return nil, errors.New("pairing code already consumed")
	}
	if time.Now().After(app.ExpiresAt) {
		return nil, errors.New("pairing code expired")
	}

	// The status and expiry guards live in the UPDATE so two concurrent claims of the same
	// code cannot both mint a token; the checks above only shape the error message.
	now := time.Now().UTC()
	q := `UPDATE paired_apps SET status = 'paired', service_name = ?, app_name = ?, paired_at = ?
	      WHERE id = ? AND status = 'pending' AND expires_at > ?`
	res, err := d.conn.ExecContext(ctx, q, serviceName, appName, now, app.ID, now)
	if err != nil {
		return nil, err
	}
	if rows, err := res.RowsAffected(); err != nil {
		return nil, err
	} else if rows == 0 {
		return nil, errors.New("pairing code already consumed")
	}

	app.Status = "paired"
	app.ServiceName = serviceName
	app.AppName = appName
	app.PairedAt = &now
	return app, nil
}

// UpdateAppLastBackup marks the latest backup time for a paired app.
func (d *DB) UpdateAppLastBackup(ctx context.Context, id string) error {
	now := time.Now().UTC()
	q := `UPDATE paired_apps SET last_backup_at = ? WHERE id = ?`
	_, err := d.conn.ExecContext(ctx, q, now, id)
	return err
}

// ListPairedApps returns all registered and pending paired applications.
func (d *DB) ListPairedApps(ctx context.Context) ([]PairedAppRecord, error) {
	q := `SELECT id, service_name, app_name, api_token, pairing_code, status, expires_at, paired_at, last_backup_at, created_at
	      FROM paired_apps ORDER BY created_at DESC`
	rows, err := d.conn.QueryContext(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []PairedAppRecord
	for rows.Next() {
		var a PairedAppRecord
		if err := rows.Scan(&a.ID, &a.ServiceName, &a.AppName, &a.APIToken, &a.PairingCode, &a.Status, &a.ExpiresAt, &a.PairedAt, &a.LastBackupAt, &a.CreatedAt); err != nil {
			return nil, err
		}
		list = append(list, a)
	}
	return list, rows.Err()
}

// RevokePairedApp revokes an active paired application token.
func (d *DB) RevokePairedApp(ctx context.Context, id string) error {
	q := `UPDATE paired_apps SET status = 'revoked' WHERE id = ?`
	_, err := d.conn.ExecContext(ctx, q, id)
	return err
}

// InsertRecoveryKey pins the suite recovery public key. Only one row is ever allowed.
func (d *DB) InsertRecoveryKey(ctx context.Context, k RecoveryKeyRecord) error {
	q := `INSERT INTO recovery_key (singleton, key_id, public_key, threshold, total_shares, imported_by, imported_at)
	      VALUES (1, ?, ?, ?, ?, ?, ?)`
	_, err := d.conn.ExecContext(ctx, q, k.KeyID, k.PublicKey, k.Threshold, k.TotalShares, k.ImportedBy, k.ImportedAt.UTC())
	if err != nil && strings.Contains(err.Error(), "UNIQUE constraint failed") {
		return ErrRecoveryKeyExists
	}
	return err
}

// GetRecoveryKey returns the pinned recovery key, or (nil, nil) if none has been imported.
func (d *DB) GetRecoveryKey(ctx context.Context) (*RecoveryKeyRecord, error) {
	q := `SELECT key_id, public_key, threshold, total_shares, imported_by, imported_at FROM recovery_key WHERE singleton = 1`
	var k RecoveryKeyRecord
	err := d.conn.QueryRowContext(ctx, q).Scan(&k.KeyID, &k.PublicKey, &k.Threshold, &k.TotalShares, &k.ImportedBy, &k.ImportedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &k, nil
}

// InsertSession stores a new user session.
func (d *DB) InsertSession(ctx context.Context, s SessionRecord) error {
	q := `INSERT INTO sessions (id, user_id, email, name, role, expires_at, created_at)
	      VALUES (?, ?, ?, ?, ?, ?, ?)`
	_, err := d.conn.ExecContext(ctx, q, s.ID, s.UserID, s.Email, s.Name, s.Role, s.ExpiresAt.UTC(), s.CreatedAt.UTC())
	return err
}

// GetSession retrieves an active session by session ID.
func (d *DB) GetSession(ctx context.Context, id string) (*SessionRecord, error) {
	q := `SELECT id, user_id, email, name, role, expires_at, created_at FROM sessions WHERE id = ?`
	row := d.conn.QueryRowContext(ctx, q, id)
	var s SessionRecord
	if err := row.Scan(&s.ID, &s.UserID, &s.Email, &s.Name, &s.Role, &s.ExpiresAt, &s.CreatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	if time.Now().UTC().After(s.ExpiresAt) {
		_ = d.DeleteSession(ctx, id)
		return nil, nil
	}
	return &s, nil
}

// DeleteUserSessionsExcept ends every session belonging to a user apart from one,
// so a password change cannot leave the old password's sessions alive.
func (d *DB) DeleteUserSessionsExcept(ctx context.Context, userID, keepSessionID string) error {
	q := `DELETE FROM sessions WHERE user_id = ? AND id != ?`
	_, err := d.conn.ExecContext(ctx, q, userID, keepSessionID)
	return err
}

// DeleteSession removes a session from SQLite.
func (d *DB) DeleteSession(ctx context.Context, id string) error {
	q := `DELETE FROM sessions WHERE id = ?`
	_, err := d.conn.ExecContext(ctx, q, id)
	return err
}

// InsertReplicationTarget creates or updates an offsite replication target.
func (d *DB) InsertReplicationTarget(ctx context.Context, t ReplicationTargetRecord) error {
	q := `INSERT INTO replication_targets (id, name, type, endpoint, bucket, region, access_key, secret_key, prefix, auto_sync, status, last_sync_at, created_at)
	      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	      ON CONFLICT(id) DO UPDATE SET
	      name=excluded.name, type=excluded.type, endpoint=excluded.endpoint, bucket=excluded.bucket,
	      region=excluded.region, access_key=excluded.access_key, secret_key=excluded.secret_key,
	      prefix=excluded.prefix, auto_sync=excluded.auto_sync, status=excluded.status`
	autoSyncInt := 0
	if t.AutoSync {
		autoSyncInt = 1
	}
	sealedSecret, err := d.keys.Seal(t.SecretKey)
	if err != nil {
		return fmt.Errorf("failed sealing replication secret key: %w", err)
	}
	_, err = d.conn.ExecContext(ctx, q, t.ID, t.Name, t.Type, t.Endpoint, t.Bucket, t.Region, t.AccessKey, sealedSecret, t.Prefix, autoSyncInt, t.Status, t.LastSyncAt, t.CreatedAt.UTC())
	return err
}

// GetReplicationTarget returns a target by ID.
func (d *DB) GetReplicationTarget(ctx context.Context, id string) (*ReplicationTargetRecord, error) {
	q := `SELECT id, name, type, endpoint, bucket, region, access_key, secret_key, prefix, auto_sync, status, last_sync_at, created_at
	      FROM replication_targets WHERE id = ?`
	row := d.conn.QueryRowContext(ctx, q, id)
	var t ReplicationTargetRecord
	var autoSyncInt int
	var err error
	if err = row.Scan(&t.ID, &t.Name, &t.Type, &t.Endpoint, &t.Bucket, &t.Region, &t.AccessKey, &t.SecretKey, &t.Prefix, &autoSyncInt, &t.Status, &t.LastSyncAt, &t.CreatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	t.AutoSync = autoSyncInt == 1
	if t.SecretKey, err = d.keys.Open(t.SecretKey); err != nil {
		return nil, err
	}
	return &t, nil
}

// ListReplicationTargets returns all configured replication targets.
func (d *DB) ListReplicationTargets(ctx context.Context) ([]ReplicationTargetRecord, error) {
	q := `SELECT id, name, type, endpoint, bucket, region, access_key, secret_key, prefix, auto_sync, status, last_sync_at, created_at
	      FROM replication_targets ORDER BY created_at ASC`
	rows, err := d.conn.QueryContext(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []ReplicationTargetRecord
	for rows.Next() {
		var t ReplicationTargetRecord
		var autoSyncInt int
		if err := rows.Scan(&t.ID, &t.Name, &t.Type, &t.Endpoint, &t.Bucket, &t.Region, &t.AccessKey, &t.SecretKey, &t.Prefix, &autoSyncInt, &t.Status, &t.LastSyncAt, &t.CreatedAt); err != nil {
			return nil, err
		}
		t.AutoSync = autoSyncInt == 1
		if t.SecretKey, err = d.keys.Open(t.SecretKey); err != nil {
			return nil, err
		}
		list = append(list, t)
	}
	return list, rows.Err()
}

// UpdateReplicationTargetLastSync updates the sync timestamp and status.
func (d *DB) UpdateReplicationTargetLastSync(ctx context.Context, id, status string) error {
	now := time.Now().UTC()
	q := `UPDATE replication_targets SET last_sync_at = ?, status = ? WHERE id = ?`
	_, err := d.conn.ExecContext(ctx, q, now, status, id)
	return err
}

// DeleteReplicationTarget deletes a target by ID.
func (d *DB) DeleteReplicationTarget(ctx context.Context, id string) error {
	q := `DELETE FROM replication_targets WHERE id = ?`
	_, err := d.conn.ExecContext(ctx, q, id)
	return err
}

// InsertReplicationLog writes a log event for a capsule replication transfer.
func (d *DB) InsertReplicationLog(ctx context.Context, l ReplicationLogRecord) error {
	q := `INSERT INTO replication_logs (target_id, capsule_id, bytes_transferred, duration_ms, status, error_message, created_at)
	      VALUES (?, ?, ?, ?, ?, ?, ?)`
	_, err := d.conn.ExecContext(ctx, q, l.TargetID, l.CapsuleID, l.BytesTransferred, l.DurationMs, l.Status, l.ErrorMessage, l.CreatedAt.UTC())
	return err
}

// ListReplicationLogs returns recent transfer logs.
func (d *DB) ListReplicationLogs(ctx context.Context, limit int) ([]ReplicationLogRecord, error) {
	if limit <= 0 {
		limit = 50
	}
	q := `SELECT id, target_id, capsule_id, bytes_transferred, duration_ms, status, error_message, created_at
	      FROM replication_logs ORDER BY created_at DESC LIMIT ?`
	rows, err := d.conn.QueryContext(ctx, q, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []ReplicationLogRecord
	for rows.Next() {
		var l ReplicationLogRecord
		if err := rows.Scan(&l.ID, &l.TargetID, &l.CapsuleID, &l.BytesTransferred, &l.DurationMs, &l.Status, &l.ErrorMessage, &l.CreatedAt); err != nil {
			return nil, err
		}
		list = append(list, l)
	}
	return list, rows.Err()
}

// InsertUser creates a new local user.
func (d *DB) InsertUser(ctx context.Context, u UserRecord) error {
	q := `INSERT INTO users (id, username, password_hash, salt, email, name, role, created_at)
	      VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
	_, err := d.conn.ExecContext(ctx, q, u.ID, u.Username, u.PasswordHash, u.Salt, u.Email, u.Name, u.Role, u.CreatedAt.UTC())
	return err
}

// GetUserByUsername finds a user by username.
func (d *DB) GetUserByUsername(ctx context.Context, username string) (*UserRecord, error) {
	q := `SELECT id, username, password_hash, salt, email, name, role, created_at FROM users WHERE username = ?`
	row := d.conn.QueryRowContext(ctx, q, username)
	var u UserRecord
	if err := row.Scan(&u.ID, &u.Username, &u.PasswordHash, &u.Salt, &u.Email, &u.Name, &u.Role, &u.CreatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return &u, nil
}

// GetUserByID finds a user by ID.
func (d *DB) GetUserByID(ctx context.Context, id string) (*UserRecord, error) {
	q := `SELECT id, username, password_hash, salt, email, name, role, created_at FROM users WHERE id = ?`
	row := d.conn.QueryRowContext(ctx, q, id)
	var u UserRecord
	if err := row.Scan(&u.ID, &u.Username, &u.PasswordHash, &u.Salt, &u.Email, &u.Name, &u.Role, &u.CreatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return &u, nil
}

// UpdateUserPassword updates the password hash and salt for a user.
func (d *DB) UpdateUserPassword(ctx context.Context, id, passwordHash, salt string) error {
	q := `UPDATE users SET password_hash = ?, salt = ? WHERE id = ?`
	_, err := d.conn.ExecContext(ctx, q, passwordHash, salt, id)
	return err
}

// CountUsers returns the total count of registered local users.
func (d *DB) CountUsers(ctx context.Context) (int, error) {
	q := `SELECT COUNT(*) FROM users`
	var count int
	err := d.conn.QueryRowContext(ctx, q).Scan(&count)
	return count, err
}

// GetSetting retrieves a system setting value by key.
func (d *DB) GetSetting(ctx context.Context, key string) (string, error) {
	q := `SELECT value FROM system_settings WHERE key = ?`
	var val string
	err := d.conn.QueryRowContext(ctx, q, key).Scan(&val)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return val, err
}

// SetSetting saves or updates a system setting value.
func (d *DB) SetSetting(ctx context.Context, key, value string) error {
	q := `INSERT INTO system_settings (key, value, updated_at) VALUES (?, ?, ?)
	      ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at`
	_, err := d.conn.ExecContext(ctx, q, key, value, time.Now().UTC())
	return err
}

// GetAllSettings returns all key-value pairs from system_settings.
func (d *DB) GetAllSettings(ctx context.Context) (map[string]string, error) {
	q := `SELECT key, value FROM system_settings`
	rows, err := d.conn.QueryContext(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	settings := make(map[string]string)
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			return nil, err
		}
		settings[k] = v
	}
	return settings, rows.Err()
}
