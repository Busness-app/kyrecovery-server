package server_test

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Busness-app/kyrecovery-server/internal/audit"
	"github.com/Busness-app/kyrecovery-server/internal/db"
	"github.com/Busness-app/kyrecovery-server/internal/pairing"
	"github.com/Busness-app/kyrecovery-server/internal/server"

	_ "modernc.org/sqlite"
)

// A client written against zero_code_pairing_handoff_spec.md must pair and push
// without knowing anything about KyRecovery's internal payload shapes.
func TestPublishedSpecClientCanPairAndPush(t *testing.T) {
	ctx := t.Context()
	database, err := db.Open(":memory:")
	if err != nil {
		t.Fatalf("db.Open failed: %v", err)
	}
	defer database.Close()

	srv, err := server.New(server.Config{Port: 8097, DataDir: t.TempDir()}, database, audit.NewLedger(database))
	if err != nil {
		t.Fatalf("server.New failed: %v", err)
	}

	pending, err := pairing.GeneratePairingCode(ctx, database, 15*time.Minute, "kynotes", "Pending Service")
	if err != nil {
		t.Fatalf("GeneratePairingCode failed: %v", err)
	}

	// Spec 2.2: claim the PIN, receive a bearer token.
	claimBody, _ := json.Marshal(map[string]string{
		"pairing_code": pending.PairingCode,
		"app_name":     "KyNotes Production Cluster US-East",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/pairing/claim", bytes.NewReader(claimBody))
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("claim expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var claim struct {
		ID       string     `json:"id"`
		APIToken string     `json:"api_token"`
		Status   string     `json:"status"`
		PairedAt *time.Time `json:"paired_at"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &claim); err != nil {
		t.Fatalf("decoding claim response failed: %v", err)
	}
	if claim.ID == "" || claim.Status != "paired" || claim.PairedAt == nil {
		t.Fatalf("claim response missing documented fields: %s", rec.Body.String())
	}
	if !strings.HasPrefix(claim.APIToken, "kyrec_live_") {
		t.Fatalf("documented token prefix missing: %s", claim.APIToken)
	}

	// Spec 2.3: push files as an array, dependencies as a declaration object, and the
	// verification contract under verification_recipe.
	pushBody, _ := json.Marshal(map[string]interface{}{
		"service_name": "kynotes",
		"app_version":  "1.4.2",
		"threshold":    2,
		"total_shares": 3,
		"files": []map[string]interface{}{
			{"path": "data/notes.db", "data_base64": base64.StdEncoding.EncodeToString(sqliteFileBytes(t)), "mode": 384},
			{"path": "certs/jwt_signing.key", "data_base64": base64.StdEncoding.EncodeToString(rsaSigningKeyPEM(t)), "mode": 384},
		},
		"dependencies": map[string]interface{}{
			"ports": []int{8080},
			"env":   []string{"KY_ISSUER", "DATABASE_URL"},
		},
		"verification_recipe": map[string]interface{}{
			"check_sqlite_integrity": true,
			"sqlite_paths":           []string{"data/notes.db"},
			"test_signing_key_path":  "certs/jwt_signing.key",
			"signing_algorithm":      "rsa",
			"required_files":         []string{"data/notes.db", "certs/jwt_signing.key"},
			"expected_env":           []string{"KY_ISSUER", "DATABASE_URL"},
			"expected_ports":         []int{8080},
		},
	})
	req = httptest.NewRequest(http.MethodPost, "/api/backup/push", bytes.NewReader(pushBody))
	req.Header.Set("Authorization", "Bearer "+claim.APIToken)
	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("spec-shaped push expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var push struct {
		Status      string `json:"status"`
		CapsuleID   string `json:"capsule_id"`
		ServiceName string `json:"service_name"`
		SizeBytes   int64  `json:"size_bytes"`
		PayloadHash string `json:"payload_hash"`
		Shares      []struct {
			Index    int    `json:"index"`
			ValueHex string `json:"value_hex"`
		} `json:"shares"`
		DrillSummary struct {
			Passed bool `json:"passed"`
			Checks []struct {
				Name    string `json:"name"`
				Passed  bool   `json:"passed"`
				Message string `json:"message"`
			} `json:"checks"`
		} `json:"drill_summary"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &push); err != nil {
		t.Fatalf("decoding push response failed: %v", err)
	}

	if push.Status != "ingested" || push.ServiceName != "kynotes" || push.SizeBytes <= 0 ||
		!strings.HasPrefix(push.CapsuleID, "cap-kynotes-") || push.PayloadHash == "" || len(push.Shares) != 3 {
		t.Fatalf("push response does not match the published shape: %s", rec.Body.String())
	}

	// Every declared check must have actually run and passed.
	ran := make(map[string]bool, len(push.DrillSummary.Checks))
	for _, check := range push.DrillSummary.Checks {
		ran[check.Name] = true
		if !check.Passed {
			t.Fatalf("declared check %q failed: %s", check.Name, check.Message)
		}
	}
	for _, name := range []string{
		"required_file:data/notes.db",
		"sqlite_check:data/notes.db",
		"signing_key:certs/jwt_signing.key",
		"expected_env",
		"expected_ports",
	} {
		if !ran[name] {
			t.Fatalf("declared check %q never ran: %s", name, rec.Body.String())
		}
	}
	if !push.DrillSummary.Passed {
		t.Fatalf("drill did not pass: %s", rec.Body.String())
	}
}

func sqliteFileBytes(t *testing.T) []byte {
	t.Helper()
	path := filepath.Join(t.TempDir(), "notes.db")
	conn, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("sql.Open failed: %v", err)
	}
	if _, err := conn.Exec("CREATE TABLE notes (id INTEGER PRIMARY KEY, body TEXT)"); err != nil {
		t.Fatalf("CREATE TABLE failed: %v", err)
	}
	conn.Close()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}
	return data
}

func rsaSigningKeyPEM(t *testing.T) []byte {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey failed: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
}

// Spec 2.2 error codes: a second claim of the same PIN is a conflict, not a bad request.
func TestClaimingASpentCodeReturnsConflict(t *testing.T) {
	ctx := t.Context()
	database, err := db.Open(":memory:")
	if err != nil {
		t.Fatalf("db.Open failed: %v", err)
	}
	defer database.Close()

	srv, err := server.New(server.Config{Port: 8098, DataDir: t.TempDir()}, database, audit.NewLedger(database))
	if err != nil {
		t.Fatalf("server.New failed: %v", err)
	}

	pending, err := pairing.GeneratePairingCode(ctx, database, 15*time.Minute, "kynotes", "Pending Service")
	if err != nil {
		t.Fatalf("GeneratePairingCode failed: %v", err)
	}

	claim := func() int {
		body, _ := json.Marshal(map[string]string{"pairing_code": pending.PairingCode, "app_name": "KyNotes"})
		req := httptest.NewRequest(http.MethodPost, "/api/pairing/claim", bytes.NewReader(body))
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, req)
		return rec.Code
	}

	if code := claim(); code != http.StatusOK {
		t.Fatalf("first claim expected 200, got %d", code)
	}
	if code := claim(); code != http.StatusConflict {
		t.Fatalf("second claim expected 409, got %d", code)
	}
}
