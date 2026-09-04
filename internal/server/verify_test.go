package server_test

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/Busness-app/ky-primitives/recoverykey"
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
