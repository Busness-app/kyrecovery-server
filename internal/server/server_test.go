package server_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"kyrecovery-server/internal/audit"
	"kyrecovery-server/internal/auth"
	"kyrecovery-server/internal/db"
	"kyrecovery-server/internal/server"
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

	srv, err := server.New(server.Config{Port: 8095, DataDir: t.TempDir()}, database, ledger)
	if err != nil {
		t.Fatalf("server.New failed: %v", err)
	}

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

	// 3. Test POST /api/capsules/capture
	capBody := []byte(`{"service_name":"kysignon","threshold":2,"total_shares":3}`)
	req = httptest.NewRequest(http.MethodPost, "/api/capsules/capture", bytes.NewReader(capBody))
	req.AddCookie(sessionCookie)
	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /api/capsules/capture expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var captureResp struct {
		Capsule db.CapsuleRecord `json:"capsule"`
		Shares  []struct {
			Index    byte   `json:"index"`
			ValueHex string `json:"value_hex"`
		} `json:"shares"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &captureResp); err != nil {
		t.Fatalf("failed decoding capture response: %v", err)
	}
	if len(captureResp.Shares) != 3 {
		t.Fatalf("expected 3 shares, got %d", len(captureResp.Shares))
	}

	// 4. Test POST /api/drills/run
	share1 := fmtShare(captureResp.Shares[0].Index, captureResp.Shares[0].ValueHex)
	share2 := fmtShare(captureResp.Shares[1].Index, captureResp.Shares[1].ValueHex)
	drillReqBody, _ := json.Marshal(map[string]interface{}{
		"capsule_id": captureResp.Capsule.ID,
		"shares":     []string{share1, share2},
	})
	req = httptest.NewRequest(http.MethodPost, "/api/drills/run", bytes.NewReader(drillReqBody))
	req.AddCookie(sessionCookie)
	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /api/drills/run expected 200, got %d: %s", rec.Code, rec.Body.String())
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

	// 8. Test POST /api/backup/push (Self-Declared Backup from paired product)
	backupBody, _ := json.Marshal(map[string]interface{}{
		"service_name": "kynotes",
		"app_name":     "KyNotes Server Primary",
		"app_version":  "v1.5.0",
		"threshold":    2,
		"total_shares": 3,
		"dependencies": []map[string]interface{}{
			{"name": "PORT_8088", "type": "port", "required": true, "description": "Notes port"},
		},
		"verify_recipe": map[string]interface{}{
			"check_sqlite_databases": true,
			"validate_json_files":    true,
		},
		"files": map[string]string{
			"data/notes.db":   "bW9jay1kYXRhYmFzZS1jb250ZW50LTEyMzQ1", // base64
			"config/app.json": "eyJzZXJ2aWNlIjogImt5bm90ZXMifQ==",
		},
	})
	req = httptest.NewRequest(http.MethodPost, "/api/backup/push", bytes.NewReader(backupBody))
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", claimResp.APIToken))
	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /api/backup/push expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var pushResp struct {
		Status   string `json:"status"`
		CapsuleID string `json:"capsule_id"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &pushResp); err != nil || pushResp.Status != "success" {
		t.Fatalf("failed parsing backup push response: %+v", pushResp)
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

	// 14. Test POST /api/ceremonies/create
	ceremonyCreateBody, _ := json.Marshal(map[string]interface{}{
		"capsule_id": captureResp.Capsule.ID,
		"purpose":    "Interactive Quorum Drill",
		"ttl_minutes": 30,
	})
	req = httptest.NewRequest(http.MethodPost, "/api/ceremonies/create", bytes.NewReader(ceremonyCreateBody))
	req.AddCookie(sessionCookie)
	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /api/ceremonies/create expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var cerSess struct {
		ID        string `json:"id"`
		Status    string `json:"status"`
		Threshold int    `json:"threshold"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &cerSess); err != nil || cerSess.ID == "" {
		t.Fatalf("failed decoding ceremony response: %v", err)
	}

	// 15. Test POST /api/ceremonies/submit (Custodian 1)
	sub1Body, _ := json.Marshal(map[string]string{
		"session_id":     cerSess.ID,
		"custodian_name": "Alice Custodian",
		"share":          share1,
	})
	req = httptest.NewRequest(http.MethodPost, "/api/ceremonies/submit", bytes.NewReader(sub1Body))
	req.AddCookie(sessionCookie)
	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /api/ceremonies/submit 1 expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	// 16. Test POST /api/ceremonies/submit (Custodian 2 -> Quorum Reached)
	sub2Body, _ := json.Marshal(map[string]string{
		"session_id":     cerSess.ID,
		"custodian_name": "Bob Custodian",
		"share":          share2,
	})
	req = httptest.NewRequest(http.MethodPost, "/api/ceremonies/submit", bytes.NewReader(sub2Body))
	req.AddCookie(sessionCookie)
	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /api/ceremonies/submit 2 expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var sub2Resp struct {
		Status string `json:"status"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &sub2Resp)
	if sub2Resp.Status != "quorum_reached" {
		t.Fatalf("expected quorum_reached, got %s", sub2Resp.Status)
	}

	// 17. Test POST /api/ceremonies/execute
	execBody, _ := json.Marshal(map[string]string{"session_id": cerSess.ID})
	req = httptest.NewRequest(http.MethodPost, "/api/ceremonies/execute", bytes.NewReader(execBody))
	req.AddCookie(sessionCookie)
	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /api/ceremonies/execute expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	// 18. Test GET /api/ceremonies
	req = httptest.NewRequest(http.MethodGet, "/api/ceremonies", nil)
	req.AddCookie(sessionCookie)
	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/ceremonies expected 200, got %d", rec.Code)
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
		"capsule_id": captureResp.Capsule.ID,
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
	req = httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/capsules/diff?base=%s&target=%s", captureResp.Capsule.ID, pushResp.CapsuleID), nil)
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

func fmtShare(idx byte, valHex string) string {
	return fmt.Sprintf("%d-%s", idx, valHex)
}
