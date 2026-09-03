package capsule

import (
	"archive/tar"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// rewriteCapsule rebuilds a .kycap tar, substituting entry bodies. A nil body
// leaves the entry untouched; this is the attacker's edit primitive.
func rewriteCapsule(t *testing.T, src string, bodies map[string][]byte) string {
	t.Helper()
	in, err := os.Open(src)
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()

	dst := filepath.Join(t.TempDir(), "tampered.kycap")
	out, err := os.Create(dst)
	if err != nil {
		t.Fatal(err)
	}
	defer out.Close()

	tr := tar.NewReader(in)
	tw := tar.NewWriter(out)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(tr)
		if err != nil {
			t.Fatal(err)
		}
		if replacement, ok := bodies[hdr.Name]; ok {
			body = replacement
		}
		hdr.Size = int64(len(body))
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(body); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return dst
}

func packStreamFixture(t *testing.T) (string, *PackResult) {
	t.Helper()
	src := t.TempDir()
	if err := os.WriteFile(filepath.Join(src, "data.db"), []byte("secret contents"), 0600); err != nil {
		t.Fatal(err)
	}
	capPath := filepath.Join(t.TempDir(), "orig.kycap")
	res, err := PackDirectoryStream(src, capPath, PackOptions{
		CapsuleID: "cap-real", ServiceName: "kypassword", Threshold: 3, TotalShares: 5,
	})
	if err != nil {
		t.Fatal(err)
	}
	return capPath, res
}

func packFileFixture(t *testing.T) (string, *PackResult) {
	t.Helper()
	res, err := Pack(PackOptions{
		CapsuleID: "cap-real", ServiceName: "kypassword", Threshold: 3, TotalShares: 5,
		Files: map[string][]byte{"data.db": []byte("secret contents")},
	})
	if err != nil {
		t.Fatal(err)
	}
	capPath := filepath.Join(t.TempDir(), "v1.kycap")
	if err := os.WriteFile(capPath, res.CapsuleBytes, 0600); err != nil {
		t.Fatal(err)
	}
	return capPath, res
}

func manifestOf(t *testing.T, capPath string) *Manifest {
	t.Helper()
	m, err := ReadManifestFromFile(capPath)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func marshal(t *testing.T, m Manifest) []byte {
	t.Helper()
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// Round trips must keep working; every rejection below is worthless if they don't.
func TestStreamRoundTripStillWorks(t *testing.T) {
	capPath, res := packStreamFixture(t)
	dest := t.TempDir()
	if _, err := UnpackToDirectoryStream(capPath, res.MasterKey, dest); err != nil {
		t.Fatalf("honest streaming capsule rejected: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(dest, "data.db"))
	if err != nil || string(got) != "secret contents" {
		t.Fatalf("payload not restored: %q %v", got, err)
	}
}

func TestFileCapsuleRoundTripStillWorks(t *testing.T) {
	capPath, res := packFileFixture(t)
	dest := t.TempDir()
	if _, err := UnpackToDirectoryStream(capPath, res.MasterKey, dest); err != nil {
		t.Fatalf("honest v1 capsule rejected: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(dest, "data.db"))
	if err != nil || string(got) != "secret contents" {
		t.Fatalf("payload not restored: %q %v", got, err)
	}
}

// Identity fields must not drift from the AAD the payload was sealed under:
// the drill runner picks its adapter from service_name before decrypting.
func TestManifestIdentityMustMatchAAD(t *testing.T) {
	for _, tc := range []struct {
		name  string
		muton func(*Manifest)
	}{
		{"service_name", func(m *Manifest) { m.ServiceName = "kysignon" }},
		{"capsule_id", func(m *Manifest) { m.CapsuleID = "cap-attacker" }},
		{"aad", func(m *Manifest) { m.AAD = "cap-attacker:kysignon" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			capPath, res := packStreamFixture(t)
			m := *manifestOf(t, capPath)
			tc.muton(&m)
			bad := rewriteCapsule(t, capPath, map[string][]byte{"manifest.json": marshal(t, m)})

			if _, err := ReadManifestFromFile(bad); err == nil {
				t.Error("ReadManifestFromFile accepted an unbound manifest")
			}
			if _, err := UnpackToDirectoryStream(bad, res.MasterKey, t.TempDir()); err == nil {
				t.Error("UnpackToDirectoryStream accepted an unbound manifest")
			}

			raw, err := os.ReadFile(bad)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := ReadManifest(raw); err == nil {
				t.Error("ReadManifest accepted an unbound manifest")
			}
		})
	}
}

func TestManifestIdentityCannotUseAmbiguousDelimiter(t *testing.T) {
	for _, pack := range []struct {
		name string
		run  func(PackOptions) error
	}{
		{"memory", func(opts PackOptions) error { _, err := Pack(opts); return err }},
		{"stream", func(opts PackOptions) error {
			_, err := PackDirectoryStream(t.TempDir(), filepath.Join(t.TempDir(), "bad.kycap"), opts)
			return err
		}},
	} {
		t.Run(pack.name, func(t *testing.T) {
			if err := pack.run(PackOptions{CapsuleID: "cap:real", ServiceName: "kypassword", Threshold: 2, TotalShares: 3}); err == nil {
				t.Fatal("colon-bearing capsule ID accepted")
			}
			if err := pack.run(PackOptions{CapsuleID: "cap-real", ServiceName: "ky:password", Threshold: 2, TotalShares: 3}); err == nil {
				t.Fatal("colon-bearing service name accepted")
			}
		})
	}

	capPath, res := packStreamFixture(t)
	m := *manifestOf(t, capPath)
	m.CapsuleID = "cap"
	m.ServiceName = "real:kypassword"
	bad := rewriteCapsule(t, capPath, map[string][]byte{"manifest.json": marshal(t, m)})
	if _, err := ReadManifestFromFile(bad); err == nil {
		t.Error("ambiguous identity split accepted before decryption")
	}
	if _, err := UnpackToDirectoryStream(bad, res.MasterKey, t.TempDir()); err == nil {
		t.Error("ambiguous identity split accepted during unpack")
	}
}

func TestConsistentManifestRewriteFailsAuthentication(t *testing.T) {
	capPath, res := packStreamFixture(t)
	m := *manifestOf(t, capPath)
	m.CapsuleID = "cap-attacker"
	m.ServiceName = "kysignon"
	m.AAD = m.CapsuleID + ":" + m.ServiceName
	bad := rewriteCapsule(t, capPath, map[string][]byte{"manifest.json": marshal(t, m)})

	// A manifest-only reader cannot authenticate public metadata without a key.
	// The unpack boundary must reject the rewrite before any consumer uses it.
	if _, err := ReadManifestFromFile(bad); err != nil {
		t.Fatalf("self-consistent public manifest rejected as malformed: %v", err)
	}
	if _, err := UnpackToDirectoryStream(bad, res.MasterKey, t.TempDir()); err == nil {
		t.Fatal("consistently rewritten identity authenticated")
	}
}

func TestFileCapsuleIdentityMustMatchAAD(t *testing.T) {
	capPath, res := packFileFixture(t)
	m := *manifestOf(t, capPath)
	m.ServiceName = "kysignon"
	bad := rewriteCapsule(t, capPath, map[string][]byte{"manifest.json": marshal(t, m)})

	raw, err := os.ReadFile(bad)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := Unpack(raw, res.MasterKey); err == nil {
		t.Error("Unpack accepted an unbound manifest")
	}
	if _, err := UnpackToDirectoryStream(bad, res.MasterKey, t.TempDir()); err == nil {
		t.Error("UnpackToDirectoryStream accepted an unbound manifest")
	}
}

// The streaming path had no payload integrity check at all.
func TestStreamPayloadHashIsVerified(t *testing.T) {
	capPath, res := packStreamFixture(t)
	m := *manifestOf(t, capPath)
	m.PayloadHash = strings.Repeat("de", 32)
	bad := rewriteCapsule(t, capPath, map[string][]byte{"manifest.json": marshal(t, m)})

	if _, err := UnpackToDirectoryStream(bad, res.MasterKey, t.TempDir()); err == nil {
		t.Fatal("streaming unpack accepted a forged payload hash")
	}
}

func TestFileCapsulePayloadHashIsVerifiedOnDiskPath(t *testing.T) {
	capPath, res := packFileFixture(t)
	m := *manifestOf(t, capPath)
	m.PayloadHash = strings.Repeat("de", 32)
	bad := rewriteCapsule(t, capPath, map[string][]byte{"manifest.json": marshal(t, m)})

	if _, err := UnpackToDirectoryStream(bad, res.MasterKey, t.TempDir()); err == nil {
		t.Fatal("on-disk v1 unpack accepted a forged payload hash")
	}
}

// Chunks are individually authenticated, so truncation is the remaining edit;
// only the payload hash catches it.
func TestStreamTruncationIsRejected(t *testing.T) {
	src := t.TempDir()
	big := make([]byte, 4*StreamChunkSize) // incompressible, so it spans several chunks
	if _, err := rand.Read(big); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "big.db"), big, 0600); err != nil {
		t.Fatal(err)
	}
	capPath := filepath.Join(t.TempDir(), "big.kycap")
	res, err := PackDirectoryStream(src, capPath, PackOptions{
		CapsuleID: "cap-real", ServiceName: "kypassword", Threshold: 2, TotalShares: 3,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Keep only the first chunk.
	in, err := os.Open(capPath)
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()
	tr := tar.NewReader(in)
	var payload []byte
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if hdr.Name == "payload.stream.enc" {
			payload, _ = io.ReadAll(tr)
		}
	}
	if len(payload) < 8 {
		t.Fatal("no streamed payload found")
	}
	first := 4 + int(binary.BigEndian.Uint32(payload[:4]))
	if first >= len(payload) {
		t.Fatal("expected more than one chunk")
	}
	bad := rewriteCapsule(t, capPath, map[string][]byte{"payload.stream.enc": payload[:first]})

	if _, err := UnpackToDirectoryStream(bad, res.MasterKey, t.TempDir()); err == nil {
		t.Fatal("truncated stream accepted")
	}
}

// A 4-byte length field must not size the allocation.
func TestOversizedChunkLengthIsRejected(t *testing.T) {
	capPath, res := packStreamFixture(t)

	bomb := make([]byte, 4, 5)
	binary.BigEndian.PutUint32(bomb, 0xFFFFFFFF)
	bomb = append(bomb, 'A')
	bad := rewriteCapsule(t, capPath, map[string][]byte{"payload.stream.enc": bomb})

	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	_, err := UnpackToDirectoryStream(bad, res.MasterKey, t.TempDir())
	runtime.ReadMemStats(&after)

	if err == nil {
		t.Fatal("oversized chunk accepted")
	}
	if grew := after.TotalAlloc - before.TotalAlloc; grew > 64<<20 {
		t.Fatalf("a %d-byte capsule drove %d bytes of allocation", 4096, grew)
	}
}

// A short nonce.bin must not reach gcm.Open: the streaming path derives the
// chunk nonce by slicing it, so an undersized one panics the whole process.
func TestShortNonceIsRejected(t *testing.T) {
	capPath, res := packStreamFixture(t)
	bad := rewriteCapsule(t, capPath, map[string][]byte{"nonce.bin": {1, 2, 3}})

	if _, err := UnpackToDirectoryStream(bad, res.MasterKey, t.TempDir()); err == nil {
		t.Fatal("short nonce accepted")
	}
}

// An early return must not strand the decrypt goroutine on pw.Write.
func TestNoGoroutineLeakOnExtractFailure(t *testing.T) {
	src := t.TempDir()
	big := make([]byte, 3*StreamChunkSize) // several chunks, so the writer blocks
	if _, err := rand.Read(big); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "big.db"), big, 0600); err != nil {
		t.Fatal(err)
	}
	capPath := filepath.Join(t.TempDir(), "big.kycap")
	res, err := PackDirectoryStream(src, capPath, PackOptions{
		CapsuleID: "cap-real", ServiceName: "kypassword", Threshold: 2, TotalShares: 3,
	})
	if err != nil {
		t.Fatal(err)
	}

	// A regular file where the destination directory should be: extraction
	// fails on its first MkdirAll, while the decrypt goroutine is mid-stream.
	blocked := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(blocked, nil, 0600); err != nil {
		t.Fatal(err)
	}

	before := runtime.NumGoroutine()
	if _, err := UnpackToDirectoryStream(capPath, res.MasterKey, blocked); err == nil {
		t.Fatal("expected extraction to fail")
	}
	for i := 0; i < 200 && runtime.NumGoroutine() > before; i++ {
		time.Sleep(5 * time.Millisecond)
	}
	if after := runtime.NumGoroutine(); after > before {
		t.Fatalf("goroutine leaked: %d before, %d after", before, after)
	}
}
