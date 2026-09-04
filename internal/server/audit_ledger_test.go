package server_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Busness-app/ky-primitives/recoverykey"
	"github.com/Busness-app/kyrecovery-server/internal/audit"
	"github.com/Busness-app/kyrecovery-server/internal/server"
)

// A ledger that cannot append is not a quiet degradation for a blind store: the audit
// trail is most of its evidence that a deposit happened. Deposits stop, and both the
// verify endpoint and readiness say why.
func TestPoisonedLedgerRefusesDepositsAndIsVisible(t *testing.T) {
	srv, cookie, database := newAdminServer(t)
	k, err := recoverykey.Generate()
	if err != nil {
		t.Fatal(err)
	}
	importKey(t, srv, cookie, k.Public(), 3, 5)
	token, _ := pairProduct(t, srv, cookie, "kynotes")

	// Someone with database access removes the tail of the log. The anchor still counts it.
	last, err := database.GetLastAuditEvent(t.Context())
	if err != nil || last == nil {
		t.Fatalf("last audit event: %v %v", last, err)
	}
	if err := database.DeleteAuditEventForTest(t.Context(), last.Seq); err != nil {
		t.Fatal(err)
	}

	poisoned, err := server.New(server.Config{Port: 8097, DataDir: t.TempDir()}, database, audit.NewLedger(database))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(poisoned.Close)

	if rec := deposit(poisoned, token, sealFor(t, k.Public(), "kynotes")); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("deposit onto a poisoned ledger: %d %s", rec.Code, rec.Body.String())
	}

	verify := ask(t, poisoned, cookie, http.MethodPost, "/api/audit/verify")
	if verify["append_disabled"] != true {
		t.Fatalf("audit verify does not report the latched ledger: %v", verify)
	}
	if verify["error"] == nil {
		t.Fatalf("audit verify reports no reason: %v", verify)
	}
	ready := ask(t, poisoned, cookie, http.MethodGet, "/api/readiness")
	if ready["audit_append_disabled"] != true {
		t.Fatalf("readiness does not report the latched ledger: %v", ready)
	}
}

func ask(t *testing.T, srv *server.Server, cookie *http.Cookie, method, path string) map[string]any {
	t.Helper()
	req := httptest.NewRequest(method, path, nil)
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()
	srv.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("%s %s: %d %s", method, path, rr.Code, rr.Body.String())
	}
	var out map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	return out
}
