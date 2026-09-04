package server_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Busness-app/kyrecovery-server/internal/auth"
)

// A share password pasted inside the SMB URL must never reach the cleartext
// endpoint column or the audit ledger.
func TestSMBTargetWithUserinfoIsRejectedAndNotRecorded(t *testing.T) {
	srv, database := newTestServer(t)
	admin := sessionCookie(t, database, auth.RoleAdmin)

	body := `{"type":"smb","name":"NAS","endpoint":"smb://ky:hunter2@nas.lan/Public","access_key":"ky","secret_key":"x"}`
	req := httptest.NewRequest(http.MethodPost, "/api/replication/targets", strings.NewReader(body))
	req.AddCookie(admin)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status %d, want 400: %s", rec.Code, rec.Body.String())
	}

	targets, err := database.ListReplicationTargets(t.Context())
	if err != nil || len(targets) != 0 {
		t.Fatalf("target was stored: %+v err=%v", targets, err)
	}

	req = httptest.NewRequest(http.MethodGet, "/api/audit", nil)
	req.AddCookie(admin)
	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if strings.Contains(rec.Body.String(), "hunter2") {
		t.Fatal("password reached the audit ledger")
	}
}
