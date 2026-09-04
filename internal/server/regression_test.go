package server_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/Busness-app/kyrecovery-server/internal/audit"
	"github.com/Busness-app/kyrecovery-server/internal/auth"
	"github.com/Busness-app/kyrecovery-server/internal/db"
	"github.com/Busness-app/kyrecovery-server/internal/server"
)

// These cover the findings of the 2026-08-22 security audit. Each one failed
// before the fix; a regression re-opens the hole it names.

// A viewer must not reach an operator-gated capsule action, however the URL is
// spelled. The policy matched a "/download" suffix while the handler trimmed the
// path, so one trailing slash used to authorize as viewer and dispatch as download.
func TestCapsuleActionGateSurvivesPathSpelling(t *testing.T) {
	database, err := db.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()

	dataDir := t.TempDir()
	srv, err := server.New(server.Config{Port: 8292, DataDir: dataDir}, database, audit.NewLedger(database))
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	viewer := sessionCookie(t, database, auth.RoleViewer)
	operator := sessionCookie(t, database, auth.RoleOperator)

	id := "cap-gate-01"
	path := filepath.Join(dataDir, "capsules", id+".kycap")
	if err := os.WriteFile(path, []byte("sealed-bytes"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := database.InsertCapsule(t.Context(), db.CapsuleRecord{
		ID: id, ServiceName: "kysignon", FilePath: path, SizeBytes: 12,
		PayloadHash: "aa", Threshold: 2, TotalShares: 3, Status: "active", CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}

	for _, path := range []string{
		"/api/capsules/" + id + "/download",
		"/api/capsules/" + id + "/download/",
		"/api/capsules/" + id + "/download//",
	} {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, path, nil)
		r.AddCookie(viewer)
		srv.ServeHTTP(w, r)
		if w.Code == http.StatusOK {
			t.Errorf("viewer reached %s: got 200 with %d bytes", path, w.Body.Len())
		}
	}

	// The operator this is gated for still gets through on the canonical path.
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/capsules/"+id+"/download", nil)
	r.AddCookie(operator)
	srv.ServeHTTP(w, r)
	if w.Code != http.StatusOK || w.Body.Len() == 0 {
		t.Fatalf("operator download broke: %d, %d bytes", w.Code, w.Body.Len())
	}
}

// requiredRole is only meaningful if a non-canonical path never reaches a handler
// under a weaker role than its canonical spelling would demand.
func TestNonCanonicalAPIPathsAreRejected(t *testing.T) {
	srv, database := newTestServer(t)
	viewer := sessionCookie(t, database, auth.RoleViewer)

	for _, path := range []string{
		"/api/capsules/cap-x/download/",
		"/api/audit/",
		"//api/audit",
		"/api/./audit",
		"/api/capsules/../audit",
	} {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, path, nil)
		r.AddCookie(viewer)
		srv.ServeHTTP(w, r)
		if w.Code == http.StatusOK {
			t.Errorf("non-canonical path %q was served: %d", path, w.Code)
		}
	}
}

// An unauthenticated caller must not choose what the audit ledger records as the
// actor of an event, and the dashboard must not render any of it as markup.
func TestFailedLoginCannotChooseTheAuditActor(t *testing.T) {
	srv, database := newTestServer(t)

	payload := `<img src=x onerror="alert(1)">`
	body, _ := json.Marshal(map[string]string{"username": payload, "password": "wrong"})
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/api/auth/login/local", strings.NewReader(string(body))))
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}

	viewer := sessionCookie(t, database, auth.RoleViewer)
	aw := httptest.NewRecorder()
	ar := httptest.NewRequest(http.MethodGet, "/api/audit", nil)
	ar.AddCookie(viewer)
	srv.ServeHTTP(aw, ar)

	var events []db.AuditRecord
	if err := json.Unmarshal(aw.Body.Bytes(), &events); err != nil {
		t.Fatalf("decode /api/audit: %v", err)
	}
	if len(events) == 0 {
		t.Fatal("the failed sign-in was not recorded at all")
	}
	for _, e := range events {
		if e.Actor == payload {
			t.Errorf("audit row #%d records an anonymous caller's string as the actor: %q", e.SequenceNum, e.Actor)
		}
	}
	// The attempt is still auditable — the claimed name is kept as a claim.
	if !strings.Contains(events[0].DetailsJSON, "claimed_username") {
		t.Errorf("the submitted username should survive in details, got %s", events[0].DetailsJSON)
	}
}

// The ledger is the last place to catch an actor string that should never have
// been caller-supplied, so it bounds what it will store.
func TestAuditActorIsBounded(t *testing.T) {
	database, err := db.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()

	ledger := audit.NewLedger(database)
	rec, err := ledger.Record(t.Context(), "test", strings.Repeat("a", 4096)+"\n\x00bad", "target", nil)
	if err != nil {
		t.Fatalf("Record failed: %v", err)
	}
	if len(rec.Actor) > 256 {
		t.Errorf("actor not truncated: %d bytes", len(rec.Actor))
	}
	if strings.ContainsAny(rec.Actor, "\n\x00") {
		t.Error("control characters survived into the actor column")
	}
}

// Product tokens and pairing codes are credentials only an admin may mint. They
// must not come back from a viewer-readable listing.
func TestPairingListLeaksNoCredentials(t *testing.T) {
	srv, database := newTestServer(t)
	admin := sessionCookie(t, database, auth.RoleAdmin)

	gw := httptest.NewRecorder()
	gr := httptest.NewRequest(http.MethodPost, "/api/pairing/generate", strings.NewReader(`{"service_name":"kypassword"}`))
	gr.AddCookie(admin)
	srv.ServeHTTP(gw, gr)
	if gw.Code != http.StatusOK {
		t.Fatalf("generate: %d %s", gw.Code, gw.Body.String())
	}
	var gen map[string]any
	if err := json.Unmarshal(gw.Body.Bytes(), &gen); err != nil {
		t.Fatal(err)
	}
	// The admin who generates the code is shown it — that is the point of the route.
	code, _ := gen["pairing_code"].(string)
	if len(code) != 6 {
		t.Fatalf("generate must still return the pairing code, got %v", gen["pairing_code"])
	}
	// But not the token, which belongs to whoever claims it.
	if _, present := gen["api_token"]; present {
		t.Error("generate returned the API token to the administrator")
	}

	apps, err := database.ListPairedApps(t.Context())
	if err != nil || len(apps) == 0 {
		t.Fatalf("ListPairedApps: %v", err)
	}
	token := apps[0].APIToken

	for _, role := range []string{auth.RoleViewer, auth.RoleOperator, auth.RoleAdmin} {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/api/pairing/list", nil)
		r.AddCookie(sessionCookie(t, database, role))
		srv.ServeHTTP(w, r)
		body := w.Body.String()
		if strings.Contains(body, token) {
			t.Errorf("%s read the product API token from /api/pairing/list", role)
		}
		if strings.Contains(body, code) {
			t.Errorf("%s read the live pairing code from /api/pairing/list", role)
		}
	}
}

// The session cookie is HttpOnly so that script cannot carry the session away.
// No response body may hand the same value over.
func TestSessionTokenNeverAppearsInAResponseBody(t *testing.T) {
	srv, database := newTestServer(t)
	c := sessionCookie(t, database, auth.RoleAdmin)

	for _, path := range []string{"/api/auth/me", "/api/readiness", "/api/capsules", "/api/audit", "/api/ceremonies"} {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, path, nil)
		r.AddCookie(c)
		srv.ServeHTTP(w, r)
		if strings.Contains(w.Body.String(), c.Value) {
			t.Errorf("%s echoed the session token: %s", path, w.Body.String())
		}
	}

	// /api/auth/me must still say who is signed in.
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/auth/me", nil)
	r.AddCookie(c)
	srv.ServeHTTP(w, r)
	var me struct {
		Authenticated bool `json:"authenticated"`
		User          struct {
			Email string `json:"email"`
			Role  string `json:"role"`
		} `json:"user"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &me); err != nil {
		t.Fatal(err)
	}
	if !me.Authenticated || me.User.Role != auth.RoleAdmin || me.User.Email == "" {
		t.Errorf("/api/auth/me no longer identifies the user: %s", w.Body.String())
	}
}

// The absolute location of a capsule on the server is not capsule metadata.
func TestCapsuleListDoesNotLeakServerPaths(t *testing.T) {
	database, err := db.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()

	dataDir := t.TempDir()
	srv, err := server.New(server.Config{Port: 8291, DataDir: dataDir}, database, audit.NewLedger(database))
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	if err := database.InsertCapsule(t.Context(), db.CapsuleRecord{
		ID: "cap-p", ServiceName: "s", FilePath: filepath.Join(dataDir, "capsules", "cap-p.kycap"),
		PayloadHash: "aa", Threshold: 2, TotalShares: 3, Status: "active", CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}

	for _, path := range []string{"/api/capsules", "/api/capsules/cap-p"} {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, path, nil)
		r.AddCookie(sessionCookie(t, database, auth.RoleViewer))
		srv.ServeHTTP(w, r)
		if strings.Contains(w.Body.String(), dataDir) {
			t.Errorf("%s leaks the server data directory: %s", path, w.Body.String())
		}
	}
}

// Escaping in the dashboard is only load-bearing if it is applied everywhere, so
// this reads the asset that actually ships and fails on a new unescaped sink.
func TestEmbeddedDashboardEscapesEveryInnerHTMLSink(t *testing.T) {
	source, err := os.ReadFile("static/js/app.js")
	if err != nil {
		t.Fatalf("reading the embedded dashboard: %v", err)
	}
	js := string(source)

	if !strings.Contains(js, "const esc =") || !strings.Contains(js, "const escJs =") {
		t.Fatal("the dashboard escaping helpers are gone")
	}

	// Interpolations that are safe without escaping: a literal-producing ternary,
	// a numeric coercion, a date, or a URL component.
	safe := regexp.MustCompile(`^\s*(esc|escJs|Number|encodeURIComponent)\(|^\s*[a-zA-Z_.]+\s*(===|!==|\?)|^\s*\(|^\s*pct\b|^\s*color\b|^\s*pillClass\b|^\s*checksHtml\b|^\s*participantsStr\b|^\s*optionsHTML\b|^\s*new Date\(`)

	templates := htmlTemplates(js)
	if len(templates) < 6 {
		t.Fatalf("only found %d HTML templates; the scanner is not reading the file it thinks it is", len(templates))
	}
	for _, block := range templates {
		for _, expr := range interpolations(block) {
			if !safe.MatchString(expr) {
				t.Errorf("unescaped value interpolated into an HTML template: ${%s}", expr)
			}
		}
	}
}

// htmlTemplates returns every backtick template literal in js whose body
// contains markup. A literal that builds a URL, a textContent string or a
// textarea value is not an HTML context and is not the concern here.
func htmlTemplates(js string) []string {
	var out []string
	for i := 0; i < len(js); i++ {
		if js[i] != '`' {
			continue
		}
		depth, j := 0, i+1
		for ; j < len(js); j++ {
			if js[j] == '\\' {
				j++
				continue
			}
			if js[j] == '$' && j+1 < len(js) && js[j+1] == '{' {
				depth++
				j++
				continue
			}
			if js[j] == '}' && depth > 0 {
				depth--
				continue
			}
			if js[j] == '`' && depth == 0 {
				break
			}
		}
		if j >= len(js) {
			break
		}
		if body := js[i+1 : j]; strings.Contains(body, "<") {
			out = append(out, body)
		}
		i = j
	}
	return out
}

// interpolations extracts the expression inside each ${...} at the top level of s.
func interpolations(s string) []string {
	var out []string
	for i := 0; i < len(s); i++ {
		if s[i] != '$' || i+1 >= len(s) || s[i+1] != '{' {
			continue
		}
		depth, j := 1, i+2
		for ; j < len(s) && depth > 0; j++ {
			switch s[j] {
			case '{':
				depth++
			case '}':
				depth--
			}
		}
		if depth == 0 {
			out = append(out, s[i+2:j-1])
			i = j - 1
		}
	}
	return out
}

// Every response carries a policy that stops injected markup reaching off-origin.
func TestContentSecurityPolicyIsServed(t *testing.T) {
	srv, _ := newTestServer(t)
	for _, path := range []string{"/", "/api/auth/me", "/static/js/app.js"} {
		w := httptest.NewRecorder()
		srv.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
		csp := w.Header().Get("Content-Security-Policy")
		if !strings.Contains(csp, "default-src 'self'") || !strings.Contains(csp, "object-src 'none'") {
			t.Errorf("%s served without a usable CSP: %q", path, csp)
		}
	}
}

// A six-digit code must not be left guessable for an arbitrary window.
func TestPairingTTLIsCapped(t *testing.T) {
	srv, database := newTestServer(t)
	admin := sessionCookie(t, database, auth.RoleAdmin)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/pairing/generate", strings.NewReader(`{"ttl_minutes":10080}`))
	r.AddCookie(admin)
	srv.ServeHTTP(w, r)
	if w.Code != http.StatusBadRequest {
		t.Errorf("a one-week pairing window was accepted: %d %s", w.Code, w.Body.String())
	}
}

// Changing a password ends the sessions that the old password opened.
func TestPasswordChangeRevokesOtherSessions(t *testing.T) {
	database, err := db.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()

	authMgr := auth.NewManager(auth.OIDCConfig{}, database)
	pass, _, err := authMgr.EnsureAdminUser(t.Context(), "OriginalPassword123!")
	if err != nil {
		t.Fatal(err)
	}
	srv, err := server.New(server.Config{Port: 8292, DataDir: t.TempDir()}, database, audit.NewLedger(database))
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	login := func() *http.Cookie {
		body, _ := json.Marshal(map[string]string{"username": "admin", "password": pass})
		w := httptest.NewRecorder()
		srv.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/api/auth/login/local", strings.NewReader(string(body))))
		if w.Code != http.StatusOK {
			t.Fatalf("login: %d %s", w.Code, w.Body.String())
		}
		return w.Result().Cookies()[0]
	}

	stale := login()
	current := login()

	body, _ := json.Marshal(map[string]string{"old_password": pass, "new_password": "ReplacementPassword123!"})
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/api/auth/password", strings.NewReader(string(body)))
	r.AddCookie(current)
	srv.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("password change: %d %s", w.Code, w.Body.String())
	}

	sw := httptest.NewRecorder()
	sr := httptest.NewRequest(http.MethodGet, "/api/capsules", nil)
	sr.AddCookie(stale)
	srv.ServeHTTP(sw, sr)
	if sw.Code != http.StatusUnauthorized {
		t.Errorf("a session opened with the old password survived the change: %d", sw.Code)
	}
}
