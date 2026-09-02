package server_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Busness-app/kyrecovery-server/internal/audit"
	"github.com/Busness-app/kyrecovery-server/internal/auth"
	"github.com/Busness-app/kyrecovery-server/internal/db"
	"github.com/Busness-app/kyrecovery-server/internal/pairing"
	"github.com/Busness-app/kyrecovery-server/internal/server"
)

func newTestServer(t *testing.T) (*server.Server, *db.DB) {
	t.Helper()
	database, err := db.Open(":memory:")
	if err != nil {
		t.Fatalf("db.Open failed: %v", err)
	}
	t.Cleanup(func() { database.Close() })

	srv, err := server.New(server.Config{Port: 8099, DataDir: t.TempDir()}, database, audit.NewLedger(database))
	if err != nil {
		t.Fatalf("server.New failed: %v", err)
	}
	t.Cleanup(srv.Close)
	return srv, database
}

// sessionCookie mints a session with the given role, standing in for a user the
// identity provider placed in that role.
func sessionCookie(t *testing.T, database *db.DB, role string) *http.Cookie {
	t.Helper()
	id := fmt.Sprintf("sess-%s-%d", role, time.Now().UnixNano())
	err := database.InsertSession(t.Context(), db.SessionRecord{
		ID:        id,
		UserID:    "usr-" + role,
		Email:     role + "@example.com",
		Name:      role,
		Role:      role,
		ExpiresAt: time.Now().UTC().Add(time.Hour),
		CreatedAt: time.Now().UTC(),
	})
	if err != nil {
		t.Fatalf("InsertSession failed: %v", err)
	}
	return &http.Cookie{Name: auth.SessionCookieName, Value: id}
}

// TestRoleEnforcementOverHTTP proves the policy table is actually applied by the
// handler chain: a viewer cannot run a ceremony, an operator cannot rotate the
// trust configuration, and an anonymous caller cannot do either.
func TestRoleEnforcementOverHTTP(t *testing.T) {
	srv, database := newTestServer(t)

	viewer := sessionCookie(t, database, auth.RoleViewer)
	operator := sessionCookie(t, database, auth.RoleOperator)
	admin := sessionCookie(t, database, auth.RoleAdmin)

	routes := []struct {
		name, method, path, body string
		minRole                  string
	}{
		{"capsule capture", http.MethodPost, "/api/capsules/capture", `{"service_name":"kysignon"}`, auth.RoleOperator},
		{"run drill", http.MethodPost, "/api/drills/run", `{"capsule_id":"cap-x"}`, auth.RoleOperator},
		{"ceremony create", http.MethodPost, "/api/ceremonies/create", `{"capsule_id":"cap-x"}`, auth.RoleOperator},
		{"ceremony submit", http.MethodPost, "/api/ceremonies/submit", `{"session_id":"s","share":"1-aa"}`, auth.RoleOperator},
		{"ceremony execute", http.MethodPost, "/api/ceremonies/execute", `{"session_id":"s"}`, auth.RoleOperator},
		{"replication sync", http.MethodPost, "/api/replication/sync", `{"capsule_id":"cap-x"}`, auth.RoleOperator},
		{"pairing generate", http.MethodPost, "/api/pairing/generate", `{}`, auth.RoleAdmin},
		{"pairing revoke", http.MethodPost, "/api/pairing/revoke", `{"id":"pair-x"}`, auth.RoleAdmin},
		{"replication target create", http.MethodPost, "/api/replication/targets", `{"type":"local","endpoint":"/tmp/x"}`, auth.RoleAdmin},
		{"replication target delete", http.MethodDelete, "/api/replication/targets/target-1", ``, auth.RoleAdmin},
		{"sso config write", http.MethodPost, "/api/auth/sso/config", `{"enabled":false}`, auth.RoleAdmin},
		{"sso connection test", http.MethodPost, "/api/auth/sso/test", `{"issuer_url":"https://example.invalid"}`, auth.RoleAdmin},
	}

	roles := []struct {
		name   string
		cookie *http.Cookie
	}{
		{auth.RoleViewer, viewer},
		{auth.RoleOperator, operator},
		{auth.RoleAdmin, admin},
	}

	for _, rt := range routes {
		// Anonymous callers never get past authentication.
		req := httptest.NewRequest(rt.method, rt.path, strings.NewReader(rt.body))
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s: anonymous expected 401, got %d", rt.name, rec.Code)
		}

		for _, role := range roles {
			req := httptest.NewRequest(rt.method, rt.path, strings.NewReader(rt.body))
			req.AddCookie(role.cookie)
			rec := httptest.NewRecorder()
			srv.ServeHTTP(rec, req)

			allowed := auth.RoleRank(role.name) >= auth.RoleRank(rt.minRole)
			if allowed && rec.Code == http.StatusForbidden {
				t.Errorf("%s: %s should be permitted but got 403", rt.name, role.name)
			}
			if !allowed && rec.Code != http.StatusForbidden {
				t.Errorf("%s: %s should be denied but got %d", rt.name, role.name, rec.Code)
			}
		}
	}
}

// TestSSOTestEndpointIsNotAnOpenSSRFPrimitive proves an unauthenticated caller
// cannot make the server reach an arbitrary URL: the target is never contacted.
func TestSSOTestEndpointIsNotAnOpenSSRFPrimitive(t *testing.T) {
	srv, database := newTestServer(t)

	var reached bool
	var mu sync.Mutex
	internalService := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		reached = true
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer internalService.Close()

	body := fmt.Sprintf(`{"issuer_url":%q}`, internalService.URL)

	for _, tc := range []struct {
		name   string
		cookie *http.Cookie
		want   int
	}{
		{"anonymous", nil, http.StatusUnauthorized},
		{"viewer", sessionCookie(t, database, auth.RoleViewer), http.StatusForbidden},
		{"operator", sessionCookie(t, database, auth.RoleOperator), http.StatusForbidden},
	} {
		req := httptest.NewRequest(http.MethodPost, "/api/auth/sso/test", strings.NewReader(body))
		if tc.cookie != nil {
			req.AddCookie(tc.cookie)
		}
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, req)
		if rec.Code != tc.want {
			t.Errorf("%s: expected %d, got %d: %s", tc.name, tc.want, rec.Code, rec.Body.String())
		}
	}

	mu.Lock()
	defer mu.Unlock()
	if reached {
		t.Fatal("a non-admin caller made the server issue an outbound request")
	}
}

// TestConcurrentPushesDoNotClobberEachOther is the recovery-integrity case: two
// backups of the same service arriving in the same second must produce two intact
// capsules, not one overwritten file.
func TestConcurrentPushesDoNotClobberEachOther(t *testing.T) {
	srv, database := newTestServer(t)
	token := pairProduct(t, srv, database, "kynotes")

	const pushes = 4
	var wg sync.WaitGroup
	results := make([]struct {
		code int
		id   string
		hash string
		body string
	}, pushes)

	for i := 0; i < pushes; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			body, _ := json.Marshal(map[string]interface{}{
				"service_name": "kynotes",
				"files": map[string]string{
					"data/notes.txt": base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("backup number %d", i))),
				},
			})
			req := httptest.NewRequest(http.MethodPost, "/api/backup/push", bytes.NewReader(body))
			req.Header.Set("Authorization", "Bearer "+token)
			rec := httptest.NewRecorder()
			srv.ServeHTTP(rec, req)

			var resp struct {
				CapsuleID   string `json:"capsule_id"`
				PayloadHash string `json:"payload_hash"`
			}
			_ = json.Unmarshal(rec.Body.Bytes(), &resp)
			results[i].code = rec.Code
			results[i].id = resp.CapsuleID
			results[i].hash = resp.PayloadHash
			results[i].body = rec.Body.String()
		}(i)
	}
	wg.Wait()

	seen := map[string]bool{}
	for i, r := range results {
		if r.code != http.StatusOK {
			t.Fatalf("push %d failed: %d %s", i, r.code, r.body)
		}
		if seen[r.id] {
			t.Fatalf("capsule ID %s was reused by two pushes", r.id)
		}
		seen[r.id] = true
	}

	// Every capsule the database describes must still exist on disk with the size
	// that was recorded for it.
	capsules, err := database.ListCapsules(t.Context())
	if err != nil {
		t.Fatalf("ListCapsules failed: %v", err)
	}
	if len(capsules) != pushes {
		t.Fatalf("expected %d capsules, got %d", pushes, len(capsules))
	}
	for _, c := range capsules {
		info, err := os.Stat(c.FilePath)
		if err != nil {
			t.Fatalf("capsule %s recorded but missing on disk: %v", c.ID, err)
		}
		if info.Size() != c.SizeBytes {
			t.Fatalf("capsule %s: recorded %d bytes, file holds %d — a later push overwrote it",
				c.ID, c.SizeBytes, info.Size())
		}
	}
}

// TestBackupPushRejectsHostilePayloads covers the bounds a compromised product
// token would otherwise be able to ignore.
func TestBackupPushRejectsHostilePayloads(t *testing.T) {
	srv, database := newTestServer(t)
	token := pairProduct(t, srv, database, "kynotes")

	push := func(payload map[string]interface{}) *httptest.ResponseRecorder {
		body, _ := json.Marshal(payload)
		req := httptest.NewRequest(http.MethodPost, "/api/backup/push", bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, req)
		return rec
	}
	oneFile := map[string]string{"a.txt": base64.StdEncoding.EncodeToString([]byte("hi"))}

	// A service name is used to build the capsule filename.
	for _, name := range []string{"../../../etc/cron.d/evil", "a/b", "..", "with space"} {
		if rec := push(map[string]interface{}{"service_name": name, "files": oneFile}); rec.Code != http.StatusBadRequest {
			t.Errorf("service_name %q expected 400, got %d: %s", name, rec.Code, rec.Body.String())
		}
	}

	// Shamir cannot produce more than 255 shares; the request must be refused
	// rather than accepted and silently reinterpreted.
	if rec := push(map[string]interface{}{
		"service_name": "kynotes", "threshold": 2, "total_shares": 100000, "files": oneFile,
	}); rec.Code != http.StatusBadRequest {
		t.Errorf("total_shares 100000 expected 400, got %d: %s", rec.Code, rec.Body.String())
	}

	// Too many files.
	many := map[string]string{}
	for i := 0; i < 5000; i++ {
		many[fmt.Sprintf("f%d.txt", i)] = base64.StdEncoding.EncodeToString([]byte("x"))
	}
	if rec := push(map[string]interface{}{"service_name": "kynotes", "files": many}); rec.Code != http.StatusBadRequest {
		t.Errorf("5000 files expected 400, got %d", rec.Code)
	}
}

// TestBackupPushBodyIsBounded proves the request body itself is capped, so a
// paired product cannot stream unbounded data into memory.
func TestBackupPushBodyIsBounded(t *testing.T) {
	t.Setenv(server.EnvMaxBackupPushBytes, "4096")
	srv, database := newTestServer(t)
	token := pairProduct(t, srv, database, "kynotes")

	body, _ := json.Marshal(map[string]interface{}{
		"service_name": "kynotes",
		"files":        map[string]string{"big.bin": base64.StdEncoding.EncodeToString(make([]byte, 64<<10))},
	})
	req := httptest.NewRequest(http.MethodPost, "/api/backup/push", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest && rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized push expected rejection, got %d: %s", rec.Code, rec.Body.String())
	}
	capsules, _ := database.ListCapsules(t.Context())
	if len(capsules) != 0 {
		t.Fatalf("an oversized push was stored anyway: %d capsules", len(capsules))
	}
}

// TestLocalLoginIsThrottled keeps an unauthenticated caller from spending the
// server's Argon2 budget, and keeps the session out of the response body.
func TestLocalLoginIsThrottled(t *testing.T) {
	srv, database := newTestServer(t)
	authMgr := auth.NewManager(auth.OIDCConfig{}, database)
	adminPass, _, err := authMgr.EnsureAdminUser(t.Context(), "CorrectHorseBatteryStaple1!")
	if err != nil {
		t.Fatalf("EnsureAdminUser failed: %v", err)
	}

	login := func(password string) *httptest.ResponseRecorder {
		body, _ := json.Marshal(map[string]string{"username": "admin", "password": password})
		req := httptest.NewRequest(http.MethodPost, "/api/auth/login/local", bytes.NewReader(body))
		req.RemoteAddr = "203.0.113.9:5555"
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, req)
		return rec
	}

	var throttled bool
	for i := 0; i < 8; i++ {
		if login("wrong-password").Code == http.StatusTooManyRequests {
			throttled = true
			break
		}
	}
	if !throttled {
		t.Fatal("repeated failed sign-ins were never throttled")
	}

	// The correct password is refused too while the account is locked out.
	if code := login(adminPass).Code; code != http.StatusTooManyRequests {
		t.Fatalf("throttle should apply to the account, got %d", code)
	}
}

func TestLoginDoesNotEchoSessionToken(t *testing.T) {
	srv, database := newTestServer(t)
	authMgr := auth.NewManager(auth.OIDCConfig{}, database)
	adminPass, _, err := authMgr.EnsureAdminUser(t.Context(), "CorrectHorseBatteryStaple1!")
	if err != nil {
		t.Fatalf("EnsureAdminUser failed: %v", err)
	}

	body, _ := json.Marshal(map[string]string{"username": "admin", "password": adminPass})
	req := httptest.NewRequest(http.MethodPost, "/api/auth/login/local", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("login failed: %d %s", rec.Code, rec.Body.String())
	}

	cookies := rec.Result().Cookies()
	if len(cookies) == 0 || cookies[0].Value == "" {
		t.Fatal("expected a session cookie")
	}
	if !cookies[0].HttpOnly {
		t.Fatal("session cookie must be HttpOnly")
	}
	if strings.Contains(rec.Body.String(), cookies[0].Value) {
		t.Fatal("the session token was echoed into the response body, exposing it to scripts")
	}
}

// TestSessionCookieIsSecureOverTLS proves a session established over HTTPS is
// marked Secure and can therefore never be replayed over plaintext HTTP.
func TestSessionCookieIsSecureOverTLS(t *testing.T) {
	srv, database := newTestServer(t)
	authMgr := auth.NewManager(auth.OIDCConfig{}, database)
	adminPass, _, err := authMgr.EnsureAdminUser(t.Context(), "CorrectHorseBatteryStaple1!")
	if err != nil {
		t.Fatalf("EnsureAdminUser failed: %v", err)
	}

	body, _ := json.Marshal(map[string]string{"username": "admin", "password": adminPass})
	req := httptest.NewRequest(http.MethodPost, "/api/auth/login/local", bytes.NewReader(body))
	req.Header.Set("X-Forwarded-Proto", "https")
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	cookies := rec.Result().Cookies()
	if len(cookies) == 0 || !cookies[0].Secure {
		t.Fatalf("a session created over HTTPS must set Secure: %+v", cookies)
	}
}

// pairProduct claims a pairing code and returns the product's API token.
func pairProduct(t *testing.T, srv *server.Server, database *db.DB, service string) string {
	t.Helper()
	pending, err := pairing.GeneratePairingCode(t.Context(), database, 15*time.Minute, service, "Pending")
	if err != nil {
		t.Fatalf("GeneratePairingCode failed: %v", err)
	}
	body, _ := json.Marshal(map[string]string{"pairing_code": pending.PairingCode, "service_name": service, "app_name": "Test Product"})
	req := httptest.NewRequest(http.MethodPost, "/api/pairing/claim", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("pairing claim failed: %d %s", rec.Code, rec.Body.String())
	}
	var claim struct {
		APIToken string `json:"api_token"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &claim); err != nil {
		t.Fatalf("decoding claim failed: %v", err)
	}
	return claim.APIToken
}
