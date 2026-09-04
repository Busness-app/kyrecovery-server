package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Busness-app/ky-primitives/capsule"
	"github.com/Busness-app/kyrecovery-server/internal/audit"
	"github.com/Busness-app/kyrecovery-server/internal/auth"
	"github.com/Busness-app/kyrecovery-server/internal/db"
)

// TestRequiredRolePolicy pins the authorization decision for every API route, for
// every role. A route added without a policy entry lands in the admin default and
// will fail here rather than silently accepting a viewer.
func TestRequiredRolePolicy(t *testing.T) {
	cases := []struct {
		method, path string
		want         string
	}{
		// Reachable without a session.
		{http.MethodGet, "/api/auth/config", rolePublic},
		{http.MethodGet, "/api/auth/me", rolePublic},
		{http.MethodGet, "/api/auth/login", rolePublic},
		{http.MethodPost, "/api/auth/login/local", rolePublic},
		{http.MethodGet, "/api/auth/callback", rolePublic},
		{http.MethodPost, "/api/auth/logout", rolePublic},
		{http.MethodGet, "/api/auth/sso/config", rolePublic},
		{http.MethodPost, "/api/pairing/claim", rolePublic},
		{http.MethodPost, "/api/backup/deposit", rolePublic}, // product bearer token, checked in the handler

		// Read-only.
		{http.MethodPost, "/api/auth/password", auth.RoleViewer},
		{http.MethodGet, "/api/readiness", auth.RoleViewer},
		{http.MethodGet, "/api/capsules", auth.RoleViewer},
		{http.MethodGet, "/api/capsules/diff", auth.RoleViewer},
		{http.MethodGet, "/api/capsules/timeline", auth.RoleViewer},
		{http.MethodGet, "/api/capsules/cap-abc", auth.RoleViewer},
		{http.MethodGet, "/api/capsules/cap-abc/verify", auth.RoleViewer},
		{http.MethodGet, "/api/custodians", auth.RoleViewer},
		{http.MethodGet, "/api/audit", auth.RoleViewer},
		{http.MethodGet, "/api/recovery-key", auth.RoleViewer}, // the public half and the topology

		{http.MethodGet, "/api/pairing/list", auth.RoleViewer},
		{http.MethodGet, "/api/replication/targets", auth.RoleViewer},
		{http.MethodGet, "/api/replication/logs", auth.RoleViewer},

		// Recovery work.
		{http.MethodGet, "/api/capsules/cap-abc/download", auth.RoleOperator},
		{http.MethodPost, "/api/custodians", auth.RoleOperator},
		{http.MethodPost, "/api/audit/verify", auth.RoleOperator},
		{http.MethodPost, "/api/replication/sync", auth.RoleOperator},

		// Trust configuration.
		{http.MethodPost, "/api/auth/sso/config", auth.RoleAdmin},
		{http.MethodPost, "/api/auth/sso/test", auth.RoleAdmin},
		{http.MethodPost, "/api/recovery-key", auth.RoleAdmin}, // pinning what the store trusts

		{http.MethodPost, "/api/pairing/generate", auth.RoleAdmin},
		{http.MethodPost, "/api/pairing/revoke", auth.RoleAdmin},
		{http.MethodPost, "/api/replication/targets", auth.RoleAdmin},
		{http.MethodPost, "/api/replication/targets/test", auth.RoleAdmin},
		{http.MethodDelete, "/api/replication/targets/target-1", auth.RoleAdmin},

		// Unknown routes are closed — including the deleted decrypting ones.
		{http.MethodPost, "/api/something/new", auth.RoleAdmin},
		{http.MethodPost, "/api/backup/push", auth.RoleAdmin},
		{http.MethodPost, "/api/v1/backup/push", auth.RoleAdmin},
		{http.MethodPost, "/api/capsules/capture", auth.RoleAdmin},
		{http.MethodPost, "/api/drills/run", auth.RoleAdmin},
		{http.MethodPost, "/api/ceremonies/execute", auth.RoleAdmin},
	}

	for _, tc := range cases {
		if got := requiredRole(tc.method, tc.path); got != tc.want {
			t.Errorf("requiredRole(%s %s) = %q, want %q", tc.method, tc.path, got, tc.want)
		}
	}
}

// TestRoleRankOrdering proves an unknown role claim cannot satisfy any check.
func TestRoleRankOrdering(t *testing.T) {
	if auth.RoleRank("unknown") != 0 || auth.RoleRank("") != 0 {
		t.Fatal("unrecognised roles must rank below viewer")
	}
	if !(auth.RoleRank(auth.RoleViewer) < auth.RoleRank(auth.RoleOperator) &&
		auth.RoleRank(auth.RoleOperator) < auth.RoleRank(auth.RoleAdmin)) {
		t.Fatal("role ranks are not ordered viewer < operator < admin")
	}
	if auth.NormalizeRole("some-idp-group") != auth.RoleViewer {
		t.Fatal("an unrecognised identity provider role must fall back to viewer")
	}
}

func TestBodyLimits(t *testing.T) {
	for _, path := range []string{"/api/capsules", "/api/pairing/claim", "/api/custodians"} {
		if bodyLimit(path) != maxAPIBodyBytes {
			t.Fatalf("%s must use the small body limit", path)
		}
	}
	// The deposit carries a sealed container, and only the deposit.
	if bodyLimit("/api/backup/deposit") != int64(capsule.MaxContainerBytes) {
		t.Fatalf("the deposit must accept a whole container, got %d", bodyLimit("/api/backup/deposit"))
	}
}

// A capsule lookup that fails for a DB reason (not "no such row") must not be reported
// as 404: that tells an operator the capsule never existed when the store is actually
// unable to answer.
func TestCapsuleDetailDBErrorIsA500NotA404(t *testing.T) {
	database, err := db.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(Config{Port: 0, DataDir: t.TempDir()}, database, audit.NewLedger(database))
	if err != nil {
		t.Fatal(err)
	}
	database.Close() // GetCapsule now returns a DB error, not sql.ErrNoRows.

	req := httptest.NewRequest(http.MethodGet, "/api/capsules/cap-x", nil)
	w := httptest.NewRecorder()
	s.handleCapsuleDetail(w, req)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("got %d %s, want 500", w.Code, w.Body.String())
	}
}

func TestValidCapsuleID(t *testing.T) {
	// The shape a sealer mints, at the widest a service name may be.
	honest := "cap-" + strings.Repeat("s", 64) + "-1788490198114479660"
	if !validCapsuleID(honest) {
		t.Fatalf("an honest capsule ID must be accepted: %q (%d bytes)", honest, len(honest))
	}
	for _, bad := range []string{"", "../../etc/passwd", "a/b", "..", "cap id", "cap\\id",
		"x..y/../z", "-leading", "cap\x00", strings.Repeat("a", 129)} {
		if validCapsuleID(bad) {
			t.Errorf("capsule ID %q must be rejected: it becomes a filename", bad)
		}
	}
}

func TestValidServiceName(t *testing.T) {
	bad := []string{"", "../../etc/passwd", "a/b", "..", "svc name", "sv\\c", "x..y/../z", string(make([]byte, 65))}
	for _, name := range bad {
		if validServiceName(name) {
			t.Errorf("service name %q must be rejected: it becomes a capsule filename", name)
		}
	}
	for _, name := range []string{"kysignon", "ky-notes", "ky_notes.v2", "A1"} {
		if !validServiceName(name) {
			t.Errorf("service name %q should be accepted", name)
		}
	}
}
