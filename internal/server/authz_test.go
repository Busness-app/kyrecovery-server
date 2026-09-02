package server

import (
	"net/http"
	"testing"

	"github.com/Busness-app/kyrecovery-server/internal/auth"
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
		{http.MethodPost, "/api/backup/push", rolePublic},
		{http.MethodPost, "/api/v1/backup/push", rolePublic},

		// Read-only.
		{http.MethodPost, "/api/auth/password", auth.RoleViewer},
		{http.MethodGet, "/api/readiness", auth.RoleViewer},
		{http.MethodGet, "/api/capsules", auth.RoleViewer},
		{http.MethodGet, "/api/capsules/diff", auth.RoleViewer},
		{http.MethodGet, "/api/capsules/timeline", auth.RoleViewer},
		{http.MethodGet, "/api/capsules/cap-abc", auth.RoleViewer},
		{http.MethodGet, "/api/custodians", auth.RoleViewer},
		{http.MethodGet, "/api/drills", auth.RoleViewer},
		{http.MethodGet, "/api/audit", auth.RoleViewer},
		{http.MethodGet, "/api/pairing/list", auth.RoleViewer},
		{http.MethodGet, "/api/ceremonies", auth.RoleViewer},
		{http.MethodGet, "/api/replication/targets", auth.RoleViewer},
		{http.MethodGet, "/api/replication/logs", auth.RoleViewer},

		// Recovery work.
		{http.MethodGet, "/api/capsules/cap-abc/download", auth.RoleOperator},
		{http.MethodGet, "/api/capsules/cap-abc/export-kit", auth.RoleOperator},
		{http.MethodPost, "/api/capsules/capture", auth.RoleOperator},
		{http.MethodPost, "/api/custodians", auth.RoleOperator},
		{http.MethodPost, "/api/drills/run", auth.RoleOperator},
		{http.MethodPost, "/api/audit/verify", auth.RoleOperator},
		{http.MethodPost, "/api/ceremonies/create", auth.RoleOperator},
		{http.MethodPost, "/api/ceremonies/submit", auth.RoleOperator},
		{http.MethodPost, "/api/ceremonies/execute", auth.RoleOperator},
		{http.MethodPost, "/api/ceremonies/cancel", auth.RoleOperator},
		{http.MethodPost, "/api/replication/sync", auth.RoleOperator},

		// Trust configuration.
		{http.MethodPost, "/api/auth/sso/config", auth.RoleAdmin},
		{http.MethodPost, "/api/auth/sso/test", auth.RoleAdmin},
		{http.MethodPost, "/api/pairing/generate", auth.RoleAdmin},
		{http.MethodPost, "/api/pairing/revoke", auth.RoleAdmin},
		{http.MethodPost, "/api/replication/targets", auth.RoleAdmin},
		{http.MethodPost, "/api/replication/targets/test", auth.RoleAdmin},
		{http.MethodDelete, "/api/replication/targets/target-1", auth.RoleAdmin},

		// Unknown routes are closed.
		{http.MethodPost, "/api/something/new", auth.RoleAdmin},
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
	if bodyLimit("/api/capsules/capture") != maxAPIBodyBytes {
		t.Fatal("ordinary API routes must use the small body limit")
	}
	if bodyLimit("/api/backup/push") != maxBackupPushBytes() {
		t.Fatal("backup push must use the backup body limit")
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
