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

	restore := requestReadBudget
	requestReadBudget = 150 * time.Millisecond // a real one is 30s; this proves the mechanism
	t.Cleanup(func() { requestReadBudget = restore })

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
