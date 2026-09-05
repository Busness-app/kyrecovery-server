package replication

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/Busness-app/ky-primitives/offsite"
	"github.com/Busness-app/kyrecovery-server/internal/db"
)

func TestTargetLocations(t *testing.T) {
	for _, prefix := range []string{"", "capsules/", "capsules", "/nested/vault/"} {
		l, err := targetLocation(db.ReplicationTargetRecord{Type: "s3", Bucket: "vault", Prefix: prefix, AccessKey: "key", SecretKey: "secret"}, "cap-KySignOn-1")
		if err != nil {
			t.Fatal(err)
		}
		if l.name != strings.TrimPrefix(prefix, "/")+"cap-KySignOn-1.kycap" || l.config.URL != "s3://vault" {
			t.Fatalf("location: %+v", l)
		}
	}
	for _, tc := range []struct {
		rec               db.ReplicationTargetRecord
		url               string
		absolute, virtual bool
	}{
		{db.ReplicationTargetRecord{Type: "sftp", Endpoint: "host", Prefix: "user/vault", AccessKey: "ky", SecretKey: "pw", HostKey: "SHA256:pin"}, "sftp://host:22/user/vault", false, false},
		{db.ReplicationTargetRecord{Type: "sftp", Endpoint: "host:2222", Prefix: "/absolute/vault"}, "sftp://host:2222/absolute/vault", true, false},
		{db.ReplicationTargetRecord{Type: "s3", Endpoint: "https://vault.example", Bucket: "vault"}, "s3://vault", false, true},
		{db.ReplicationTargetRecord{Type: "smb", Endpoint: `\\nas\Public\Vault`, AccessKey: `DOMAIN\ky`, SecretKey: "pw"}, "smb://nas:445/Public/Vault", false, false},
		{db.ReplicationTargetRecord{Type: "local", Endpoint: "/tmp/a #?b", SecretKey: "ignored"}, "file:///tmp/a%20%23%3Fb", false, false},
	} {
		l, err := targetLocation(tc.rec, "cap-KySignOn-1")
		if err != nil {
			t.Fatal(err)
		}
		if l.config.URL != tc.url || l.absoluteSFTP != tc.absolute || l.virtualS3 != tc.virtual {
			t.Fatalf("unexpected mapping: %+v", l)
		}
		if tc.rec.Type == "sftp" && (l.config.AccessKey != tc.rec.AccessKey || l.config.Secret != tc.rec.SecretKey || l.config.HostKey != tc.rec.HostKey) {
			t.Fatal("credential or pin lost")
		}
	}
	a, _ := targetLocation(db.ReplicationTargetRecord{Type: "smb", Endpoint: "host", Bucket: "share"}, "cap-Notes-1")
	b, _ := targetLocation(db.ReplicationTargetRecord{Type: "smb", Endpoint: "host", Bucket: "share"}, "cap-notes-1")
	if a.name == b.name || a.name != strings.ToLower(a.name) {
		t.Fatal("SMB case variants collide")
	}
	for _, endpoint := range []string{"http://host", "https://user:secret@host", "https://host?secret=x"} {
		if _, err := targetLocation(db.ReplicationTargetRecord{Type: "s3", Endpoint: endpoint}, "cap-one"); err == nil || strings.Contains(err.Error(), "secret=x") {
			t.Fatal("unsafe endpoint accepted or leaked")
		}
	}
}

func TestReplicaReceiptAndClose(t *testing.T) {
	data := "sealed capsule"
	rec := &db.CapsuleRecord{SizeBytes: int64(len(data)), Digest: fmt.Sprintf("%x", sha256.Sum256([]byte(data)))}
	for _, s := range []string{data, "corrupt", data + "extra"} {
		r := &trackingReader{Reader: strings.NewReader(s)}
		err := matchesReplica(r, rec)
		if (err == nil) != (s == data) || !r.closed {
			t.Fatalf("receipt match=%v closed=%v", err, r.closed)
		}
	}
}

type trackingReader struct {
	io.Reader
	closed bool
}

func (r *trackingReader) Close() error { r.closed = true; return nil }

func TestS3AdapterRoundTripAndNoRedirect(t *testing.T) {
	var stored []byte
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/vault/capsulescap-KySignOn-1.kycap" {
			t.Errorf("changed object path: %s", r.URL.Path)
		}
		if !strings.Contains(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256") {
			t.Error("unsigned request")
		}
		switch r.Method {
		case "PUT":
			stored, _ = io.ReadAll(r.Body)
		case "GET":
			w.Write(stored)
		}
	}))
	defer srv.Close()
	// Trust only this fixture's TLS certificate for the library's default transport.
	old := http.DefaultTransport
	http.DefaultTransport = srv.Client().Transport
	defer func() { http.DefaultTransport = old }()
	l, err := targetLocation(db.ReplicationTargetRecord{Type: "s3", Endpoint: srv.URL, Bucket: "vault", Prefix: "capsules", AccessKey: "ky", SecretKey: "pw"}, "cap-KySignOn-1")
	if err != nil {
		t.Fatal(err)
	}
	target, err := offsite.Parse(l.config)
	if err != nil {
		t.Fatal(err)
	}
	if err := target.Put(t.Context(), l.name, strings.NewReader("sealed"), 6); err != nil {
		t.Fatal(err)
	}
	r, err := target.Get(t.Context(), l.name)
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(r)
	r.Close()
	if err != nil || string(data) != "sealed" {
		t.Fatal("round trip failed")
	}
	redirect := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, srv.URL+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	defer redirect.Close()
	http.DefaultTransport = redirect.Client().Transport
	l.config.S3Endpoint = redirect.URL
	target, err = offsite.Parse(l.config)
	if err != nil {
		t.Fatal(err)
	}
	if err := target.Put(context.Background(), l.name, strings.NewReader("bad"), 3); err == nil {
		t.Fatal("redirect accepted")
	}
	if string(stored) != "sealed" {
		t.Fatal("redirect overwrote replica")
	}
}

func TestLocalMissingAndSymlink(t *testing.T) {
	dir := t.TempDir()
	l, err := targetLocation(db.ReplicationTargetRecord{Type: "local", Endpoint: dir}, "cap-one")
	if err != nil {
		t.Fatal(err)
	}
	target, err := offsite.Parse(l.config)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := target.Get(t.Context(), l.name); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing: %v", err)
	}
	if err := os.Symlink(t.TempDir(), dir+"/escape"); err != nil {
		t.Skip(err)
	}
	if err := target.Put(t.Context(), "escape/cap-one.kycap", strings.NewReader("sealed"), 6); err == nil {
		t.Fatal("symlink escape accepted")
	}
}

func TestInterruptedLocalPutPreservesReplica(t *testing.T) {
	dir := t.TempDir()
	l, _ := targetLocation(db.ReplicationTargetRecord{Type: "local", Endpoint: dir}, "cap-one")
	target, err := offsite.Parse(l.config)
	if err != nil {
		t.Fatal(err)
	}
	if err := target.Put(t.Context(), l.name, strings.NewReader("complete"), 8); err != nil {
		t.Fatal(err)
	}
	if err := target.Put(t.Context(), l.name, io.MultiReader(strings.NewReader("partial"), brokenReader{}), 20); err == nil {
		t.Fatal("interrupted upload accepted")
	}
	data, err := os.ReadFile(dir + "/" + l.name)
	if err != nil || string(data) != "complete" {
		t.Fatal("previous replica lost")
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 1 {
		t.Fatal("staging file leaked")
	}
}

type brokenReader struct{}

func (brokenReader) Read([]byte) (int, error) { return 0, errors.New("interrupted fixture") }

func TestLegacySMBLookup(t *testing.T) {
	c := newLegacySMB(db.ReplicationTargetRecord{Endpoint: "127.0.0.1:1", Bucket: "vault"})
	for _, name := range []string{"backup-123.kycap", "notes.kycap", "../cap-x.kycap", "cap-x:stream.kycap"} {
		if _, err := c.get(t.Context(), name); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%q: want absent without dial, got %v", name, err)
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := c.get(ctx, "cap-Notes-123.kycap"); err == nil || errors.Is(err, os.ErrNotExist) {
		t.Fatalf("legacy name should reach lookup: %v", err)
	}
}
