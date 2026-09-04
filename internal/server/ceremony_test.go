package server_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Busness-app/ky-primitives/recoverykey"
	"github.com/Busness-app/ky-primitives/shamir"
	"github.com/Busness-app/kyrecovery-server/internal/auth"
)

// The WASM module calls exactly Generate and Split. This test pins that any k of the n
// share strings it prints reconstruct the key whose public half it posts. It is the only
// place outside a product where the recovery private key is combined, and it is a test.
func TestCeremonySharesReconstructTheKey(t *testing.T) {
	priv, err := recoverykey.Generate()
	if err != nil {
		t.Fatal(err)
	}
	shares, err := recoverykey.Split(priv, 3, 5)
	if err != nil {
		t.Fatal(err)
	}
	var cards []shamir.Share
	for _, i := range []int{0, 2, 4} { // non-consecutive on purpose
		s, err := shamir.ParseShare(shares[i].String())
		if err != nil {
			t.Fatal(err)
		}
		cards = append(cards, s)
	}
	got, err := recoverykey.Combine(cards)
	if err != nil {
		t.Fatal(err)
	}
	if got.Public().ID() != priv.Public().ID() {
		t.Fatal("combined key does not match the published public key")
	}
}

// The ceremony page holds the private key while it runs, so only an admin may load it,
// and only it gets the CSP that lets a WASM module compile.
func TestCeremonyPageIsAdminOnly(t *testing.T) {
	srv, admin, database := newAdminServer(t)

	for _, tc := range []struct {
		name   string
		cookie *http.Cookie
		want   int
	}{
		{"no session", nil, http.StatusForbidden},
		{"viewer", sessionCookie(t, database, auth.RoleViewer), http.StatusForbidden},
		{"admin", admin, http.StatusOK},
	} {
		r := httptest.NewRequest(http.MethodGet, "/admin/ceremony", nil)
		if tc.cookie != nil {
			r.AddCookie(tc.cookie)
		}
		w := httptest.NewRecorder()
		srv.ServeHTTP(w, r)
		if w.Code != tc.want {
			t.Fatalf("%s: got %d, want %d", tc.name, w.Code, tc.want)
		}
		csp := w.Header().Get("Content-Security-Policy")
		if tc.want == http.StatusOK && !strings.Contains(csp, "'wasm-unsafe-eval'") {
			t.Fatalf("%s: ceremony CSP lacks wasm-unsafe-eval: %q", tc.name, csp)
		}
		if tc.want != http.StatusOK && strings.Contains(csp, "wasm-unsafe-eval") {
			t.Fatalf("%s: refused response carries the ceremony CSP: %q", tc.name, csp)
		}
	}

	// The relaxation is scoped to the ceremony: the dashboard must not get it.
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))
	if strings.Contains(w.Header().Get("Content-Security-Policy"), "wasm-unsafe-eval") {
		t.Fatal("the dashboard CSP allows wasm-unsafe-eval")
	}
}

// A browser refuses to instantiate a module served as anything but application/wasm.
func TestCeremonyWasmContentType(t *testing.T) {
	srv, _, _ := newAdminServer(t)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/static/wasm/ceremony.wasm", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("got %d", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/wasm" {
		t.Fatalf("Content-Type %q, want application/wasm", ct)
	}
}

// The cards are only useful on paper: printed black on white, with the share string
// wrapped rather than clipped at the page edge. Neither can be asserted headlessly, so
// this pins the two rules that make them true.
func TestCeremonyPrintStylesAreServed(t *testing.T) {
	srv, _, _ := newAdminServer(t)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/static/css/ceremony.css", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("got %d", w.Code)
	}
	for _, rule := range []string{"@media print", "overflow-wrap: anywhere"} {
		if !strings.Contains(w.Body.String(), rule) {
			t.Errorf("ceremony.css is missing %q", rule)
		}
	}
}
