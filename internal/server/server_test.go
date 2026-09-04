package server_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Busness-app/kyrecovery-server/internal/audit"
	"github.com/Busness-app/kyrecovery-server/internal/auth"
	"github.com/Busness-app/kyrecovery-server/internal/db"
	"github.com/Busness-app/kyrecovery-server/internal/pairing"
	"github.com/Busness-app/kyrecovery-server/internal/server"
)

func TestServerEndpoints(t *testing.T) {
	database, err := db.Open(":memory:")
	if err != nil {
		t.Fatalf("db.Open failed: %v", err)
	}
	defer database.Close()

	ledger := audit.NewLedger(database)
	authMgr := auth.NewManager(auth.OIDCConfig{}, database)
	adminPass, _, err := authMgr.EnsureAdminUser(t.Context(), "TestAdminPassword123!")
	if err != nil {
		t.Fatalf("EnsureAdminUser failed: %v", err)
	}

	dataDir := t.TempDir()
	srv, err := server.New(server.Config{Port: 8095, DataDir: dataDir}, database, ledger)
	if err != nil {
		t.Fatalf("server.New failed: %v", err)
	}

	// The store holds sealed bytes it cannot read, so the tests below deposit
	// records directly rather than through a handler that would have to decrypt.
	baseID, targetID := seedCapsule(t, database, dataDir, "kysignon", "hash-a"), seedCapsule(t, database, dataDir, "kysignon", "hash-b")

	// 0a. Test GET /favicon.svg & /favicon.ico
	favReq := httptest.NewRequest(http.MethodGet, "/favicon.svg", nil)
	favRec := httptest.NewRecorder()
	srv.ServeHTTP(favRec, favReq)
	if favRec.Code != http.StatusOK || favRec.Header().Get("Content-Type") != "image/svg+xml" {
		t.Fatalf("GET /favicon.svg expected 200 image/svg+xml, got %d %s", favRec.Code, favRec.Header().Get("Content-Type"))
	}

	favIcoReq := httptest.NewRequest(http.MethodGet, "/favicon.ico", nil)
	favIcoRec := httptest.NewRecorder()
	srv.ServeHTTP(favIcoRec, favIcoReq)
	if favIcoRec.Code != http.StatusOK {
		t.Fatalf("GET /favicon.ico expected 200, got %d", favIcoRec.Code)
	}

	// 0b. Test POST /api/auth/login/local
	loginBody, _ := json.Marshal(map[string]string{
		"username": "admin",
		"password": adminPass,
	})
	loginReq := httptest.NewRequest(http.MethodPost, "/api/auth/login/local", bytes.NewReader(loginBody))
	loginRec := httptest.NewRecorder()
	srv.ServeHTTP(loginRec, loginReq)
	if loginRec.Code != http.StatusOK {
		t.Fatalf("POST /api/auth/login/local expected 200, got %d: %s", loginRec.Code, loginRec.Body.String())
	}

	sessionCookie := loginRec.Result().Cookies()[0]
	if sessionCookie == nil || sessionCookie.Value == "" {
		t.Fatalf("expected session cookie from login")
	}

	// 1. Test GET /api/readiness
	req := httptest.NewRequest(http.MethodGet, "/api/readiness", nil)
	req.AddCookie(sessionCookie)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/readiness expected 200, got %d", rec.Code)
	}

	// 2. Test POST /api/custodians
	custBody := []byte(`{"name":"Alice","email":"alice@example.com"}`)
	req = httptest.NewRequest(http.MethodPost, "/api/custodians", bytes.NewReader(custBody))
	req.AddCookie(sessionCookie)
	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /api/custodians expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	// 5. Test POST /api/audit/verify
	req = httptest.NewRequest(http.MethodPost, "/api/audit/verify", nil)
	req.AddCookie(sessionCookie)
	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /api/audit/verify expected 200, got %d", rec.Code)
	}

	var verifyResp struct {
		Valid bool  `json:"valid"`
		Count int64 `json:"count"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &verifyResp); err != nil || !verifyResp.Valid {
		t.Fatalf("audit verify failed: %+v", verifyResp)
	}

	// 6. Test POST /api/pairing/generate
	pairGenBody := []byte(`{"ttl_minutes": 15, "service_name": "kynotes", "app_name": "KyNotes Prod"}`)
	req = httptest.NewRequest(http.MethodPost, "/api/pairing/generate", bytes.NewReader(pairGenBody))
	req.AddCookie(sessionCookie)
	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /api/pairing/generate expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var pairGenResp struct {
		PairingCode string `json:"pairing_code"`
		Status      string `json:"status"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &pairGenResp); err != nil || pairGenResp.PairingCode == "" {
		t.Fatalf("failed parsing pairing gen resp: %v", err)
	}

	// 7. Test POST /api/pairing/claim (from client app)
	claimBody, _ := json.Marshal(map[string]string{
		"pairing_code": pairGenResp.PairingCode,
		"service_name": "kynotes",
		"app_name":     "KyNotes Server Primary",
	})
	req = httptest.NewRequest(http.MethodPost, "/api/pairing/claim", bytes.NewReader(claimBody))
	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /api/pairing/claim expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var claimResp struct {
		APIToken    string `json:"api_token"`
		ServiceName string `json:"service_name"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &claimResp); err != nil || claimResp.APIToken == "" {
		t.Fatalf("failed parsing claim resp: %v", err)
	}

	// 9. Test GET /api/pairing/list
	req = httptest.NewRequest(http.MethodGet, "/api/pairing/list", nil)
	req.AddCookie(sessionCookie)
	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/pairing/list expected 200, got %d", rec.Code)
	}

	// 10. Test GET /api/auth/config
	req = httptest.NewRequest(http.MethodGet, "/api/auth/config", nil)
	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/auth/config expected 200, got %d", rec.Code)
	}

	// 11. Test GET /api/auth/me
	req = httptest.NewRequest(http.MethodGet, "/api/auth/me", nil)
	req.AddCookie(sessionCookie)
	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/auth/me expected 200, got %d", rec.Code)
	}

	// 12. Test POST /api/auth/sso/config
	ssoSaveBody, _ := json.Marshal(map[string]interface{}{
		"enabled":       true,
		"issuer_url":    "https://auth.kysecurity.local",
		"client_id":     "kyrecovery-test-client",
		"client_secret": "secret123456",
		"redirect_url":  "http://localhost:8095/api/auth/callback",
		"admin_email":   "admin@kysecurity.local",
	})
	req = httptest.NewRequest(http.MethodPost, "/api/auth/sso/config", bytes.NewReader(ssoSaveBody))
	req.AddCookie(sessionCookie)
	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /api/auth/sso/config expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	// 13. Test GET /api/auth/sso/config
	req = httptest.NewRequest(http.MethodGet, "/api/auth/sso/config", nil)
	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/auth/sso/config expected 200, got %d", rec.Code)
	}

	// 19. Test POST /api/replication/targets (Add Local Target)
	localVaultDir := t.TempDir()
	targetBody, _ := json.Marshal(map[string]interface{}{
		"id":        "target-vault-01",
		"name":      "Local Cold Vault",
		"type":      "local",
		"endpoint":  localVaultDir,
		"auto_sync": true,
	})
	req = httptest.NewRequest(http.MethodPost, "/api/replication/targets", bytes.NewReader(targetBody))
	req.AddCookie(sessionCookie)
	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /api/replication/targets expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	// 20. Test GET /api/replication/targets
	req = httptest.NewRequest(http.MethodGet, "/api/replication/targets", nil)
	req.AddCookie(sessionCookie)
	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/replication/targets expected 200, got %d", rec.Code)
	}

	// 21. Test POST /api/replication/targets/test
	req = httptest.NewRequest(http.MethodPost, "/api/replication/targets/test", bytes.NewReader(targetBody))
	req.AddCookie(sessionCookie)
	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /api/replication/targets/test expected 200, got %d", rec.Code)
	}

	// 22. Test POST /api/replication/sync
	syncBody, _ := json.Marshal(map[string]string{
		"capsule_id": baseID,
		"target_id":  "target-vault-01",
	})
	req = httptest.NewRequest(http.MethodPost, "/api/replication/sync", bytes.NewReader(syncBody))
	req.AddCookie(sessionCookie)
	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /api/replication/sync expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	// 23. Test GET /api/replication/logs
	req = httptest.NewRequest(http.MethodGet, "/api/replication/logs", nil)
	req.AddCookie(sessionCookie)
	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/replication/logs expected 200, got %d", rec.Code)
	}

	// 24. Test GET /api/capsules/diff
	req = httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/capsules/diff?base=%s&target=%s", baseID, targetID), nil)
	req.AddCookie(sessionCookie)
	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/capsules/diff expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	// 25. Test GET /api/capsules/timeline
	req = httptest.NewRequest(http.MethodGet, "/api/capsules/timeline?service=kysignon", nil)
	req.AddCookie(sessionCookie)
	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/capsules/timeline expected 200, got %d", rec.Code)
	}

	// 26. Test POST /api/auth/password
	passChangeBody, _ := json.Marshal(map[string]string{
		"old_password": adminPass,
		"new_password": "BrandNewAdminPassword456!",
	})
	req = httptest.NewRequest(http.MethodPost, "/api/auth/password", bytes.NewReader(passChangeBody))
	req.AddCookie(sessionCookie)
	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /api/auth/password expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	// 27. Test POST /api/auth/logout
	req = httptest.NewRequest(http.MethodPost, "/api/auth/logout", nil)
	req.AddCookie(sessionCookie)
	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /api/auth/logout expected 200, got %d", rec.Code)
	}
}

// seedCapsule records a deposited capsule and its file, returning the capsule ID.
func seedCapsule(t *testing.T, database *db.DB, dataDir, service, payloadHash string) string {
	t.Helper()
	id := fmt.Sprintf("cap-%s-%s", service, payloadHash)
	path := filepath.Join(dataDir, "capsules", id+".kycap")
	if err := os.WriteFile(path, []byte("sealed-"+payloadHash), 0600); err != nil {
		t.Fatalf("writing capsule file failed: %v", err)
	}
	rec := db.CapsuleRecord{
		ID: id, ServiceName: service, FilePath: path, SizeBytes: 16,
		PayloadHash: payloadHash, Threshold: 2, TotalShares: 3,
		Status: "active", CreatedAt: time.Now().UTC(),
	}
	if err := database.InsertCapsule(t.Context(), rec); err != nil {
		t.Fatalf("InsertCapsule failed: %v", err)
	}
	return id
}

// Unauthenticated claim attempts are capped per source address.
func TestPairingClaimIsRateLimited(t *testing.T) {
	database, err := db.Open(":memory:")
	if err != nil {
		t.Fatalf("db.Open failed: %v", err)
	}
	defer database.Close()

	srv, err := server.New(server.Config{Port: 8096, DataDir: t.TempDir()}, database, audit.NewLedger(database))
	if err != nil {
		t.Fatalf("server.New failed: %v", err)
	}

	claim := func(code string) int {
		body, _ := json.Marshal(map[string]string{"pairing_code": code, "app_name": "guesser"})
		req := httptest.NewRequest(http.MethodPost, "/api/pairing/claim", bytes.NewReader(body))
		req.RemoteAddr = "203.0.113.7:51000"
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, req)
		return rec.Code
	}

	// Each guess is a different (wrong) code, so only the per-address cap can stop it.
	for i := 0; i < 10; i++ {
		if code := claim(fmt.Sprintf("%06d", 100000+i)); code != http.StatusBadRequest {
			t.Fatalf("guess %d: expected 400, got %d", i, code)
		}
	}
	if code := claim("999999"); code != http.StatusTooManyRequests {
		t.Fatalf("expected 429 after exhausting the per-address budget, got %d", code)
	}

	// A different address still gets its own budget.
	body, _ := json.Marshal(map[string]string{"pairing_code": "999998", "app_name": "other"})
	req := httptest.NewRequest(http.MethodPost, "/api/pairing/claim", bytes.NewReader(body))
	req.RemoteAddr = "203.0.113.8:51000"
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("unrelated address expected 400, got %d", rec.Code)
	}
}

// Legitimate pairings must not consume the abuse budget, or a NAT'd host that pairs
// several services would lock itself out.
func TestSuccessfulClaimsDoNotConsumeRateBudget(t *testing.T) {
	ctx := t.Context()
	database, err := db.Open(":memory:")
	if err != nil {
		t.Fatalf("db.Open failed: %v", err)
	}
	defer database.Close()

	srv, err := server.New(server.Config{Port: 8099, DataDir: t.TempDir()}, database, audit.NewLedger(database))
	if err != nil {
		t.Fatalf("server.New failed: %v", err)
	}

	for i := 0; i < 15; i++ {
		pending, err := pairing.GeneratePairingCode(ctx, database, 15*time.Minute, "kynotes", "Pending Service")
		if err != nil {
			t.Fatalf("GeneratePairingCode failed: %v", err)
		}
		body, _ := json.Marshal(map[string]string{
			"pairing_code": pending.PairingCode,
			"app_name":     fmt.Sprintf("KyNotes Node %d", i),
		})
		req := httptest.NewRequest(http.MethodPost, "/api/pairing/claim", bytes.NewReader(body))
		req.RemoteAddr = "198.51.100.4:44000" // one shared NAT address
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("pairing %d from a shared address expected 200, got %d: %s", i, rec.Code, rec.Body.String())
		}
	}
}
