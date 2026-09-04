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

	for _, ep := range []string{"smb://ky:hunter2@nas.lan/Public", "smb://ky:hun/ter2@nas.lan/Public"} {
		body := `{"type":"smb","name":"NAS","endpoint":"` + ep + `","access_key":"ky","secret_key":"x"}`
		req := httptest.NewRequest(http.MethodPost, "/api/replication/targets", strings.NewReader(body))
		req.AddCookie(admin)
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("%q: status %d, want 400: %s", ep, rec.Code, rec.Body.String())
		}
	}

	targets, err := database.ListReplicationTargets(t.Context())
	if err != nil || len(targets) != 0 {
		t.Fatalf("target was stored: %+v err=%v", targets, err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/audit", nil)
	req.AddCookie(admin)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	for _, fragment := range []string{"hunter2", "hun/ter2", "hun", "ter2@"} {
		if strings.Contains(rec.Body.String(), fragment) {
			t.Fatalf("password fragment %q reached the audit ledger", fragment)
		}
	}
}

// A pasted //host/share/dir must land in the stored share and directory
// when those fields were left blank, not be replaced by the defaults.
func TestSMBTargetPathFillsShareAndDirectory(t *testing.T) {
	srv, database := newTestServer(t)
	admin := sessionCookie(t, database, auth.RoleAdmin)

	body := `{"type":"smb","name":"NAS","endpoint":"//nas.lan/Public/vault","access_key":"ky","secret_key":"x"}`
	req := httptest.NewRequest(http.MethodPost, "/api/replication/targets", strings.NewReader(body))
	req.AddCookie(admin)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body.String())
	}
	targets, err := database.ListReplicationTargets(t.Context())
	if err != nil || len(targets) != 1 {
		t.Fatalf("targets=%+v err=%v", targets, err)
	}
	got := targets[0]
	if got.Endpoint != "nas.lan:445" || got.Bucket != "Public" || got.Prefix != "vault" {
		t.Fatalf("stored endpoint=%q bucket=%q prefix=%q", got.Endpoint, got.Bucket, got.Prefix)
	}
}
