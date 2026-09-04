package server_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/Busness-app/ky-primitives/capsule"
	"github.com/Busness-app/ky-primitives/recoverykey"
	"github.com/Busness-app/kyrecovery-server/internal/db"
	"github.com/Busness-app/kyrecovery-server/internal/server"
)

// pairProduct generates a code as admin and claims it as the product, returning the token
// and the claim body.
func pairProduct(t *testing.T, srv *server.Server, cookie *http.Cookie, service string) (string, map[string]any) {
	t.Helper()
	body, _ := json.Marshal(map[string]any{"ttl_minutes": 10, "service_name": service, "app_name": service})
	req := httptest.NewRequest(http.MethodPost, "/api/pairing/generate", bytes.NewReader(body))
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("generate: %d %s", rec.Code, rec.Body.String())
	}
	var gen struct {
		PairingCode string `json:"pairing_code"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &gen)
	body, _ = json.Marshal(map[string]string{"pairing_code": gen.PairingCode, "service_name": service, "app_name": service})
	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/pairing/claim", bytes.NewReader(body)))
	if rec.Code != http.StatusOK {
		t.Fatalf("claim: %d %s", rec.Code, rec.Body.String())
	}
	var claim map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &claim)
	return claim["api_token"].(string), claim
}

func sealFor(t *testing.T, pub recoverykey.PublicKey, service string) []byte {
	t.Helper()
	raw, _, err := capsule.Seal(service, "1.0.0", []capsule.File{{Path: "data/x.db", Content: []byte("payload"), Mode: 0600}}, nil, nil, 3, 5, pub)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func deposit(srv *server.Server, token string, body []byte) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/api/backup/deposit", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/octet-stream")
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	return rec
}

func TestClaimIsRefusedUntilAKeyIsImported(t *testing.T) {
	srv, cookie, _ := newAdminServer(t)
	body, _ := json.Marshal(map[string]any{"ttl_minutes": 10, "service_name": "kynotes", "app_name": "kynotes"})
	req := httptest.NewRequest(http.MethodPost, "/api/pairing/generate", bytes.NewReader(body))
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	var gen struct {
		PairingCode string `json:"pairing_code"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &gen)
	body, _ = json.Marshal(map[string]string{"pairing_code": gen.PairingCode, "service_name": "kynotes", "app_name": "kynotes"})
	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/pairing/claim", bytes.NewReader(body)))
	if rec.Code != http.StatusConflict {
		t.Fatalf("claim without key: %d, want 409", rec.Code)
	}
	// The code was not consumed: the same claim succeeds after import.
	k, _ := recoverykey.Generate()
	importKey(t, srv, cookie, k.Public(), 3, 5)
	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/pairing/claim", bytes.NewReader(body)))
	if rec.Code != http.StatusOK {
		t.Fatalf("claim after import: %d %s", rec.Code, rec.Body.String())
	}
}

func TestClaimHandsOutThePinnedKey(t *testing.T) {
	srv, cookie, database := newAdminServer(t)
	k, _ := recoverykey.Generate()
	importKey(t, srv, cookie, k.Public(), 3, 5)
	_, claim := pairProduct(t, srv, cookie, "kynotes")
	if claim["recovery_public_key"] != base64.StdEncoding.EncodeToString(k.Public().Bytes()) {
		t.Fatal("claim did not carry the pinned public key")
	}
	if int(claim["threshold"].(float64)) != 3 || int(claim["total_shares"].(float64)) != 5 {
		t.Fatalf("topology %v/%v", claim["threshold"], claim["total_shares"])
	}
	apps, _ := database.ListPairedApps(t.Context())
	if len(apps) != 1 || apps[0].RecoveryKeyID != k.Public().ID() {
		t.Fatalf("paired app did not record the key ID: %+v", apps)
	}
}

func TestDepositAcceptsACapsuleSealedToThePinnedKey(t *testing.T) {
	srv, cookie, database := newAdminServer(t)
	k, _ := recoverykey.Generate()
	importKey(t, srv, cookie, k.Public(), 3, 5)
	token, _ := pairProduct(t, srv, cookie, "kynotes")
	raw := sealFor(t, k.Public(), "kynotes")

	rec := deposit(srv, token, raw)
	if rec.Code != http.StatusCreated {
		t.Fatalf("deposit: %d %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		CapsuleID string `json:"capsule_id"`
		Digest    string `json:"digest"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	sum := sha256.Sum256(raw)
	if resp.Digest != hex.EncodeToString(sum[:]) {
		t.Fatalf("digest %s", resp.Digest)
	}
	stored, _ := database.GetCapsule(t.Context(), resp.CapsuleID)
	m, _ := capsule.ReadUnverifiedManifest(raw)
	if stored == nil || stored.RecoveryKeyID != k.Public().ID() || stored.PayloadHash != m.PayloadHash || stored.ServiceName != "kynotes" || stored.SizeBytes != int64(len(raw)) {
		t.Fatalf("record %+v", stored)
	}
	// Re-sending the same bytes is idempotent.
	if rec := deposit(srv, token, raw); rec.Code != http.StatusOK {
		t.Fatalf("duplicate deposit: %d %s", rec.Code, rec.Body.String())
	}
	// Download returns the exact bytes with the digest.
	req := httptest.NewRequest(http.MethodGet, "/api/capsules/"+resp.CapsuleID+"/download", nil)
	req.AddCookie(cookie)
	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !bytes.Equal(rec.Body.Bytes(), raw) || rec.Header().Get("X-Capsule-Digest") != resp.Digest {
		t.Fatalf("download: %d digest=%q", rec.Code, rec.Header().Get("X-Capsule-Digest"))
	}
	// Sealed bytes leaving the store is an auditable event.
	events, _ := database.ListAuditEvents(t.Context(), 50)
	downloaded := false
	for _, e := range events {
		if e.Action == "capsule_downloaded" && e.TargetID == resp.CapsuleID {
			downloaded = true
		}
	}
	if !downloaded {
		t.Fatalf("download was not recorded in the audit chain: %+v", events)
	}
}

func TestDepositRefusals(t *testing.T) {
	srv, cookie, _ := newAdminServer(t)
	k, _ := recoverykey.Generate()
	other, _ := recoverykey.Generate()
	importKey(t, srv, cookie, k.Public(), 3, 5)
	token, _ := pairProduct(t, srv, cookie, "kynotes")

	cases := []struct {
		name  string
		body  func() []byte
		want  int
		heavy bool
	}{
		{name: "not a container", body: func() []byte { return []byte("hello") }, want: http.StatusBadRequest},
		{name: "sealed to another key", body: func() []byte { return sealFor(t, other.Public(), "kynotes") }, want: http.StatusConflict},
		{name: "another service", body: func() []byte { return sealFor(t, k.Public(), "kypost") }, want: http.StatusForbidden},
		{name: "over the cap", body: func() []byte { return bytes.Repeat([]byte{'x'}, int(capsule.MaxContainerBytes)+1) },
			want: http.StatusRequestEntityTooLarge, heavy: true},
	}
	for _, tc := range cases {
		if tc.heavy && testing.Short() {
			continue // allocating 384 MiB is the point of this row, and -short says not to
		}
		if rec := deposit(srv, token, tc.body()); rec.Code != tc.want {
			t.Errorf("%s: %d, want %d (%s)", tc.name, rec.Code, tc.want, rec.Body.String())
		}
	}
	if rec := deposit(srv, "kyrec_live_bogus", sealFor(t, k.Public(), "kynotes")); rec.Code != http.StatusUnauthorized {
		t.Errorf("bad token: %d", rec.Code)
	}
}

// A product that retries a deposit while the first is still in flight must not be able to
// destroy the capsule the first one stored. The database row is the mutex; the file follows.
func TestConcurrentIdenticalDepositsStoreExactlyOneCapsule(t *testing.T) {
	srv, cookie, database := newAdminServer(t)
	k, _ := recoverykey.Generate()
	importKey(t, srv, cookie, k.Public(), 3, 5)
	token, _ := pairProduct(t, srv, cookie, "kynotes")
	raw := sealFor(t, k.Public(), "kynotes")
	m, err := capsule.ReadUnverifiedManifest(raw)
	if err != nil {
		t.Fatal(err)
	}

	const racers = 8
	codes := make([]int, racers)
	var start sync.WaitGroup
	var done sync.WaitGroup
	start.Add(1)
	for i := range racers {
		done.Add(1)
		go func() {
			defer done.Done()
			start.Wait()
			codes[i] = deposit(srv, token, raw).Code
		}()
	}
	start.Done()
	done.Wait()

	created := 0
	for i, code := range codes {
		switch code {
		case http.StatusCreated:
			created++
		case http.StatusOK:
		default:
			t.Errorf("racer %d: %d, want 200 or 201", i, code)
		}
	}
	if created != 1 {
		t.Errorf("%d racers were told they created the capsule, want exactly 1", created)
	}

	all, err := database.ListCapsules(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 1 || all[0].ID != m.CapsuleID {
		t.Fatalf("want exactly one row for %s, got %+v", m.CapsuleID, all)
	}
	// The row must describe a file that is actually there and actually the deposited bytes.
	onDisk, err := os.ReadFile(all[0].FilePath)
	if err != nil {
		t.Fatalf("the stored capsule is gone: %v", err)
	}
	sum := sha256.Sum256(onDisk)
	if hex.EncodeToString(sum[:]) != all[0].Digest || !bytes.Equal(onDisk, raw) {
		t.Fatalf("the stored file does not match the recorded digest")
	}
	// No temporary file was left behind by the losers.
	leftovers, _ := filepath.Glob(filepath.Join(filepath.Dir(all[0].FilePath), "*.tmp*"))
	if len(leftovers) != 0 {
		t.Errorf("racing deposits left temporary files: %v", leftovers)
	}
}

// TestDepositRefusesACrashOrphanedRow covers a row inserted (e.g. by a crash between the
// insert and the rename in publishCapsule) whose file never made it to disk. A retry of the
// same ID must not be told the deposit succeeded.
func TestDepositRefusesACrashOrphanedRow(t *testing.T) {
	srv, cookie, database := newAdminServer(t)
	k, _ := recoverykey.Generate()
	importKey(t, srv, cookie, k.Public(), 3, 5)
	token, _ := pairProduct(t, srv, cookie, "kynotes")
	raw := sealFor(t, k.Public(), "kynotes")

	m, err := capsule.ReadUnverifiedManifest(raw)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	if err := database.InsertCapsule(t.Context(), db.CapsuleRecord{
		ID: m.CapsuleID, ServiceName: m.ServiceName, AppVersion: m.AppVersion,
		FilePath: filepath.Join(t.TempDir(), "missing.kycap"), SizeBytes: int64(len(raw)),
		Digest: hex.EncodeToString(sum[:]), PayloadHash: m.PayloadHash, Threshold: m.Threshold,
		TotalShares: m.TotalShares, RecoveryKeyID: m.RecoveryKeyID, EncapsulatedKey: m.EncapsulatedKey,
		CreatedAt: m.CreatedAt, DepositedAt: time.Now().UTC(), Status: "active",
	}); err != nil {
		t.Fatal(err)
	}

	rec := deposit(srv, token, raw)
	if rec.Code != http.StatusConflict {
		t.Fatalf("deposit of orphaned ID: %d %s, want 409", rec.Code, rec.Body.String())
	}
	after, err := database.GetCapsule(t.Context(), m.CapsuleID)
	if err != nil {
		t.Fatal(err)
	}
	if after.Status != "corrupt" {
		t.Fatalf("status %q, want corrupt", after.Status)
	}
}

// seedRecoveryKey pins a recovery key straight into the database, for tests that only need
// pairing to be possible and do not exercise the import route.
func seedRecoveryKey(t *testing.T, database *db.DB) recoverykey.PublicKey {
	t.Helper()
	k, err := recoverykey.Generate()
	if err != nil {
		t.Fatal(err)
	}
	pub := k.Public()
	if err := database.InsertRecoveryKey(t.Context(), db.RecoveryKeyRecord{
		KeyID: pub.ID(), PublicKey: pub.Bytes(), Threshold: 3, TotalShares: 5,
		ImportedBy: "test", ImportedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	return pub
}

// A deposit carries a whole sealed container, so the read runs on the route's own
// budget. A listener-wide ReadTimeout would cut a slow upload off mid-body and the
// product would see a misleading 400 instead of finishing. The timeout here is far
// shorter than a real one so the proof fits in a unit test.
func TestSlowDepositOutlivesTheListenerReadTimeout(t *testing.T) {
	srv, cookie, _ := newAdminServer(t)
	k, _ := recoverykey.Generate()
	importKey(t, srv, cookie, k.Public(), 3, 5)
	token, _ := pairProduct(t, srv, cookie, "kynotes")
	raw := sealFor(t, k.Public(), "kynotes")

	ts := httptest.NewUnstartedServer(srv)
	ts.Config.ReadTimeout = 150 * time.Millisecond
	ts.Start()
	defer ts.Close()

	pr, pw := io.Pipe()
	go func() {
		chunk := (len(raw) + 3) / 4
		for off := 0; off < len(raw); off += chunk {
			time.Sleep(100 * time.Millisecond) // 4 chunks: the body takes ~400ms
			if _, err := pw.Write(raw[off:min(off+chunk, len(raw))]); err != nil {
				break
			}
		}
		pw.Close()
	}()

	req, err := http.NewRequest(http.MethodPost, ts.URL+"/api/backup/deposit", pr)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatalf("slow deposit failed to complete: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("slow deposit: %d %s", resp.StatusCode, body)
	}
}
