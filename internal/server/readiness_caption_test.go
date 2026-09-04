package server_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Busness-app/kyrecovery-server/internal/auth"
)

// The overview shows custodian_count as a directory size. The reconstruction
// quorum comes only from the recovery-key record, so readiness must not start
// carrying threshold or total_shares, which a caption could mistake for one.
func TestReadinessReportsCustodianCountNotQuorum(t *testing.T) {
	srv, database := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/api/readiness", nil)
	req.AddCookie(sessionCookie(t, database, auth.RoleViewer))
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if _, ok := body["custodian_count"]; !ok {
		t.Fatal("custodian_count missing")
	}
	for _, k := range []string{"threshold", "total_shares", "quorum"} {
		if _, ok := body[k]; ok {
			t.Fatalf("readiness must not report %q; the quorum belongs to /api/recovery-key", k)
		}
	}
}
