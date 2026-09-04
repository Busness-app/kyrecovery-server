package server_test

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Busness-app/ky-primitives/capsule"
	"github.com/Busness-app/ky-primitives/recoverykey"
	"github.com/Busness-app/kyrecovery-server/internal/db"
)

func TestVerifyDetectsAFlippedByte(t *testing.T) {
	srv, cookie, database := newAdminServer(t)
	k, _ := recoverykey.Generate()
	importKey(t, srv, cookie, k.Public(), 3, 5)
	token, _ := pairProduct(t, srv, cookie, "kynotes")
	raw := sealFor(t, k.Public(), "kynotes")
	rec := deposit(srv, token, raw)
	if rec.Code != http.StatusCreated {
		t.Fatalf("deposit: %d", rec.Code)
	}
	caps, _ := database.ListCapsules(t.Context())
	id := caps[0].ID

	verify := func() (int, string) {
		req := httptest.NewRequest(http.MethodGet, "/api/capsules/"+id+"/verify", nil)
		req.AddCookie(cookie)
		rr := httptest.NewRecorder()
		srv.ServeHTTP(rr, req)
		return rr.Code, rr.Body.String()
	}
	if code, body := verify(); code != http.StatusOK || !strings.Contains(body, `"valid":true`) {
		t.Fatalf("intact: %d %s", code, body)
	}

	data, _ := os.ReadFile(caps[0].FilePath)
	data[len(data)/2] ^= 0x01
	if err := os.WriteFile(caps[0].FilePath, data, 0600); err != nil {
		t.Fatal(err)
	}
	if code, body := verify(); code != http.StatusOK || !strings.Contains(body, `"valid":false`) {
		t.Fatalf("flipped: %d %s", code, body)
	}
	after, _ := database.GetCapsule(t.Context(), id)
	if after.Status != "corrupt" {
		t.Fatalf("status %q", after.Status)
	}
}

// A row whose file is gone (a crash-orphaned insert, or media loss) is the strongest
// possible evidence of corruption: it must be flagged, not treated as an error the sweep
// cannot make progress past.
func TestVerifyOfAMissingFileFlagsCorrupt(t *testing.T) {
	srv, cookie, database := newAdminServer(t)
	k, _ := recoverykey.Generate()
	importKey(t, srv, cookie, k.Public(), 3, 5)
	raw := sealFor(t, k.Public(), "kynotes")
	m, err := capsule.ReadUnverifiedManifest(raw)
	if err != nil {
		t.Fatal(err)
	}
	rec := db.CapsuleRecord{
		ID: m.CapsuleID, ServiceName: m.ServiceName, AppVersion: m.AppVersion,
		FilePath: filepath.Join(t.TempDir(), "gone.kycap"), SizeBytes: int64(len(raw)),
		Digest: "deadbeef", PayloadHash: m.PayloadHash, Threshold: m.Threshold, TotalShares: m.TotalShares,
		RecoveryKeyID: m.RecoveryKeyID, EncapsulatedKey: m.EncapsulatedKey,
		CreatedAt: m.CreatedAt, DepositedAt: time.Now().UTC(), Status: "active",
	}
	if err := database.InsertCapsule(t.Context(), rec); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/capsules/"+rec.ID+"/verify", nil)
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()
	srv.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `"valid":false`) {
		t.Fatalf("verify of a missing file: %d %s, want 200 valid:false", rr.Code, rr.Body.String())
	}

	after, err := database.GetCapsule(t.Context(), rec.ID)
	if err != nil || after == nil {
		t.Fatalf("GetCapsule: %v", err)
	}
	if after.Status != "corrupt" {
		t.Fatalf("status %q, want corrupt", after.Status)
	}

	events, err := database.ListAuditEvents(t.Context(), 50)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, e := range events {
		if e.Action == "capsule_corrupt" && e.TargetID == rec.ID {
			found = true
		}
	}
	if !found {
		t.Fatal("no capsule_corrupt audit event for the missing-file capsule")
	}
}

// An on-demand verify must attribute the audit event to whoever asked for it, not to the
// unattended sweep: "who checked this just now" and "the nightly job found this" are
// different questions.
func TestVerifyRecordsTheCallerAsActor(t *testing.T) {
	srv, cookie, database := newAdminServer(t)
	k, _ := recoverykey.Generate()
	importKey(t, srv, cookie, k.Public(), 3, 5)
	token, _ := pairProduct(t, srv, cookie, "kynotes")
	raw := sealFor(t, k.Public(), "kynotes")
	rec := deposit(srv, token, raw)
	if rec.Code != http.StatusCreated {
		t.Fatalf("deposit: %d", rec.Code)
	}
	caps, _ := database.ListCapsules(t.Context())
	id := caps[0].ID

	req := httptest.NewRequest(http.MethodGet, "/api/capsules/"+id+"/verify", nil)
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()
	srv.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("verify: %d %s", rr.Code, rr.Body.String())
	}

	events, err := database.ListAuditEvents(t.Context(), 50)
	if err != nil {
		t.Fatal(err)
	}
	var actor string
	for _, e := range events {
		if e.Action == "capsule_verified" && e.TargetID == id {
			actor = e.Actor
		}
	}
	if actor == "" || actor == "integrity-sweep" {
		t.Fatalf("capsule_verified actor = %q, want the admin caller", actor)
	}
}
