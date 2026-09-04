package server

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Busness-app/kyrecovery-server/internal/audit"
	"github.com/Busness-app/kyrecovery-server/internal/db"
)

// trickle delivers one byte per interval, the shape of a client that never finishes a
// request it never intended to finish.
type trickle struct {
	left     int
	interval time.Duration
}

func (t *trickle) Read(p []byte) (int, error) {
	time.Sleep(t.interval)
	if t.left <= 0 {
		return 0, io.EOF
	}
	t.left--
	p[0] = ' '
	return 1, nil
}

// The listener has no ReadTimeout, so the per-request read deadline is the only thing
// bounding how long a body may take. MaxBytesReader caps the bytes and nothing else:
// without this a byte-a-second client holds a goroutine on a 1 MiB route indefinitely.
func TestASlowBodyOnASmallRouteIsCutOff(t *testing.T) {
	database, err := db.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	s, err := New(Config{Port: 0, DataDir: t.TempDir()}, database, audit.NewLedger(database))
	if err != nil {
		t.Fatal(err)
	}

	s.readBudget = 150 * time.Millisecond // a real one is 30s; this proves the mechanism

	ts := httptest.NewServer(s)
	defer ts.Close()

	req, err := http.NewRequest(http.MethodPost, ts.URL+"/api/auth/login/local", &trickle{left: 30, interval: 100 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")

	start := time.Now()
	resp, err := ts.Client().Do(req)
	elapsed := time.Since(start)
	if err == nil {
		defer resp.Body.Close()
	}
	if elapsed > 1500*time.Millisecond {
		t.Fatalf("a trickled body held the request for %v; the read deadline did not fire", elapsed)
	}
	if err == nil && resp.StatusCode/100 == 2 {
		t.Fatalf("a body that never arrived was accepted: %d", resp.StatusCode)
	}
}

// Only a request with a body is clocked. net/http reads ahead on the connection while the
// handler runs, so a read deadline on a body-less request cancels its context when it
// expires — which would kill a verify re-hashing a large container on slow storage, or an
// SSO callback waiting on an identity provider, in the middle of honest work.
func TestOnlyRequestsWithABodyAreClocked(t *testing.T) {
	cases := []struct {
		name          string
		contentLength int64
		want          bool
	}{
		{"GET with no body", 0, false},
		{"POST with a body", 42, true},
		{"chunked body of unknown length", -1, true},
	}
	for _, tc := range cases {
		r := httptest.NewRequest(http.MethodPost, "/api/capsules", nil)
		r.ContentLength = tc.contentLength
		if got := requestHasBody(r); got != tc.want {
			t.Errorf("%s: requestHasBody = %v, want %v", tc.name, got, tc.want)
		}
	}
}
