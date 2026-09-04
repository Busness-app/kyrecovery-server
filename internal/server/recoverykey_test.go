package server_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Busness-app/ky-primitives/recoverykey"
	"github.com/Busness-app/kyrecovery-server/internal/audit"
	"github.com/Busness-app/kyrecovery-server/internal/auth"
	"github.com/Busness-app/kyrecovery-server/internal/db"
	"github.com/Busness-app/kyrecovery-server/internal/server"
)

// newAdminServer mirrors server_test.go's inline setup: in-memory DB, local admin login,
// and the session cookie every admin request needs.
func newAdminServer(t *testing.T) (*server.Server, *http.Cookie, *db.DB) {
	t.Helper()
	database, err := db.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	ledger := audit.NewLedger(database)
	authMgr := auth.NewManager(auth.OIDCConfig{}, database)
	adminPass, _, err := authMgr.EnsureAdminUser(t.Context(), "TestAdminPassword123!")
	if err != nil {
		t.Fatal(err)
	}
	srv, err := server.New(server.Config{Port: 8095, DataDir: t.TempDir()}, database, ledger)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(map[string]string{"username": "admin", "password": adminPass})
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/auth/login/local", bytes.NewReader(body)))
	if rec.Code != http.StatusOK {
		t.Fatalf("login: %d %s", rec.Code, rec.Body.String())
	}
	return srv, rec.Result().Cookies()[0], database
}

func importKey(t *testing.T, srv *server.Server, cookie *http.Cookie, pub recoverykey.PublicKey, k, n int) *httptest.ResponseRecorder {
	t.Helper()
	body, _ := json.Marshal(map[string]any{
		"public_key": base64.StdEncoding.EncodeToString(pub.Bytes()), "threshold": k, "total_shares": n,
	})
	req := httptest.NewRequest(http.MethodPost, "/api/recovery-key", bytes.NewReader(body))
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	return rec
}

func TestRecoveryKeyImportIsSingleShot(t *testing.T) {
	srv, cookie, database := newAdminServer(t)
	a, _ := recoverykey.Generate() // test-only: the private half never leaves this test
	b, _ := recoverykey.Generate()

	if rec := importKey(t, srv, cookie, a.Public(), 3, 5); rec.Code != http.StatusCreated {
		t.Fatalf("first import: %d %s", rec.Code, rec.Body.String())
	}
	if rec := importKey(t, srv, cookie, b.Public(), 3, 5); rec.Code != http.StatusConflict {
		t.Fatalf("second import: %d, want 409", rec.Code)
	}
	stored, err := database.GetRecoveryKey(t.Context())
	if err != nil || stored == nil || stored.KeyID != a.Public().ID() {
		t.Fatalf("pin changed or missing: %+v %v", stored, err)
	}
	if stored.Threshold != 3 || stored.TotalShares != 5 {
		t.Fatalf("topology %d/%d", stored.Threshold, stored.TotalShares)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/recovery-key", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	var got struct {
		KeyID     string `json:"key_id"`
		PublicKey string `json:"public_key"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &got)
	if got.KeyID != a.Public().ID() || got.PublicKey != base64.StdEncoding.EncodeToString(a.Public().Bytes()) {
		t.Fatalf("GET returned %+v", got)
	}
}

func TestRecoveryKeyImportRefusesBadInput(t *testing.T) {
	srv, cookie, _ := newAdminServer(t)
	a, _ := recoverykey.Generate()
	short := a.Public().Bytes()[:100]
	body, _ := json.Marshal(map[string]any{"public_key": base64.StdEncoding.EncodeToString(short), "threshold": 2, "total_shares": 3})
	req := httptest.NewRequest(http.MethodPost, "/api/recovery-key", bytes.NewReader(body))
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("short key: %d", rec.Code)
	}
	for _, kn := range [][2]int{{0, 0}, {1, 3}, {4, 3}, {2, 256}} {
		if rec := importKey(t, srv, cookie, a.Public(), kn[0], kn[1]); rec.Code != http.StatusBadRequest {
			t.Fatalf("topology %v: %d", kn, rec.Code)
		}
	}
	// A body carrying shares is refused outright: the server must never see one.
	body, _ = json.Marshal(map[string]any{"public_key": base64.StdEncoding.EncodeToString(a.Public().Bytes()), "threshold": 2, "total_shares": 3, "shares": []string{"ky2-x"}})
	req = httptest.NewRequest(http.MethodPost, "/api/recovery-key", bytes.NewReader(body))
	req.AddCookie(cookie)
	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("body with shares: %d", rec.Code)
	}
}
