package replication_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"

	"github.com/Busness-app/kyrecovery-server/internal/audit"
	"github.com/Busness-app/kyrecovery-server/internal/db"
	"github.com/Busness-app/kyrecovery-server/internal/replication"
)

const sftpUser, sftpPass = "ky", "correct-horse"

// seenPasswords records every password the test server was offered.
var (
	seenMu        sync.Mutex
	seenPasswords []string
)

// startSFTPServer runs a password-authenticated SSH server with the sftp
// subsystem on a loopback port, serving the real filesystem.
func startSFTPServer(t *testing.T, roots ...string) (addr, fingerprint string) {
	return startSFTPServerWithHandlers(t, nil, roots...)
}

func startSFTPServerWithHandlers(t *testing.T, handlers *sftp.Handlers, roots ...string) (addr, fingerprint string) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, pw []byte) (*ssh.Permissions, error) {
			seenMu.Lock()
			seenPasswords = append(seenPasswords, string(pw))
			seenMu.Unlock()
			if c.User() == sftpUser && string(pw) == sftpPass {
				return nil, nil
			}
			return nil, errors.New("bad credentials")
		},
	}
	cfg.AddHostKey(signer)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				sconn, chans, reqs, err := ssh.NewServerConn(conn, cfg)
				if err != nil {
					return
				}
				defer sconn.Close()
				go ssh.DiscardRequests(reqs)
				for newCh := range chans {
					ch, chReqs, err := newCh.Accept()
					if err != nil {
						continue
					}
					go func(ch ssh.Channel, chReqs <-chan *ssh.Request) {
						for req := range chReqs {
							ok := req.Type == "subsystem" && len(req.Payload) >= 4 && string(req.Payload[4:]) == "sftp"
							req.Reply(ok, nil)
							if ok {
								if handlers != nil {
									srv := sftp.NewRequestServer(ch, *handlers)
									_ = srv.Serve()
									_ = srv.Close()
									return
								}
								var opts []sftp.ServerOption
								if len(roots) > 0 {
									opts = append(opts, sftp.WithServerWorkingDirectory(roots[0]))
								}
								srv, err := sftp.NewServer(ch, opts...)
								if err == nil {
									srv.Serve()
								}
								ch.Close()
								return
							}
						}
					}(ch, chReqs)
				}
			}()
		}
	}()
	return ln.Addr().String(), ssh.FingerprintSHA256(signer.PublicKey())
}

func newCapsuleFixture(t *testing.T) (*db.DB, *replication.Manager, string) {
	t.Helper()
	ctx := context.Background()
	database, err := db.Open(":memory:")
	if err != nil {
		t.Fatalf("db.Open failed: %v", err)
	}
	t.Cleanup(func() { database.Close() })
	mgr := replication.NewManager(database, audit.NewLedger(database))

	capFilePath := filepath.Join(t.TempDir(), "cap-sftp-1.kycap")
	if err := os.WriteFile(capFilePath, []byte("mock-encrypted-capsule-content"), 0600); err != nil {
		t.Fatal(err)
	}
	capRec := db.CapsuleRecord{
		ID: "cap-sftp-1", ServiceName: "kysignon", FilePath: capFilePath, SizeBytes: 30,
		Digest: fmt.Sprintf("%x", sha256.Sum256([]byte("mock-encrypted-capsule-content"))), PayloadHash: "abc", Threshold: 2, TotalShares: 3, Status: "active", CreatedAt: time.Now().UTC(),
	}
	if err := database.InsertCapsule(ctx, capRec); err != nil {
		t.Fatal(err)
	}
	return database, mgr, capRec.ID
}

func sftpTarget(addr, hostKey, dir string) db.ReplicationTargetRecord {
	return db.ReplicationTargetRecord{
		ID: "target-sftp-01", Name: "SFTP Vault", Type: "sftp",
		Endpoint: addr, AccessKey: sftpUser, SecretKey: sftpPass,
		Prefix: dir + "/", HostKey: hostKey,
		AutoSync: true, Status: "active", CreatedAt: time.Now().UTC(),
	}
}

func TestSFTPReplication(t *testing.T) {
	ctx := context.Background()
	addr, fp := startSFTPServer(t)
	database, mgr, capID := newCapsuleFixture(t)
	vault := filepath.Join(t.TempDir(), "vault")

	target := sftpTarget(addr, fp, vault)
	if err := database.InsertReplicationTarget(ctx, target); err != nil {
		t.Fatal(err)
	}
	if err := mgr.TestTarget(ctx, target); err != nil {
		t.Fatalf("TestTarget failed: %v", err)
	}
	logRec, err := mgr.SyncCapsule(ctx, capID, target.ID)
	if err != nil {
		t.Fatalf("SyncCapsule failed: %v", err)
	}
	if logRec.Status != "success" || logRec.BytesTransferred != 30 {
		t.Fatalf("unexpected log record: %+v", logRec)
	}
	data, err := os.ReadFile(filepath.Join(vault, capID+".kycap"))
	if err != nil || string(data) != "mock-encrypted-capsule-content" {
		t.Fatalf("replicated file mismatch or missing: %v", err)
	}

	// A second sync must replace the existing replica and leave no part file.
	if _, err := mgr.SyncCapsule(ctx, capID, target.ID); err != nil {
		t.Fatalf("second SyncCapsule failed: %v", err)
	}
	entries, _ := os.ReadDir(vault)
	if len(entries) != 1 || entries[0].Name() != capID+".kycap" {
		t.Fatalf("vault should hold exactly the replica, got %v", entries)
	}
}

func TestSFTPRefusesMismatchedHostKey(t *testing.T) {
	ctx := context.Background()
	addr, _ := startSFTPServer(t)
	database, mgr, capID := newCapsuleFixture(t)

	target := sftpTarget(addr, "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", t.TempDir())
	if err := database.InsertReplicationTarget(ctx, target); err != nil {
		t.Fatal(err)
	}
	if err := mgr.TestTarget(ctx, target); err == nil {
		t.Fatal("TestTarget accepted a server whose host key does not match the pin")
	}
	logRec, err := mgr.SyncCapsule(ctx, capID, target.ID)
	if err == nil || logRec.Status != "failed" {
		t.Fatalf("SyncCapsule should fail on host key mismatch, got err=%v rec=%+v", err, logRec)
	}
}

func TestSFTPUnpinnedTargetReportsFingerprint(t *testing.T) {
	addr, fp := startSFTPServer(t)
	_, mgr, _ := newCapsuleFixture(t)

	err := mgr.TestTarget(context.Background(), sftpTarget(addr, "", t.TempDir()))
	var unknown *replication.UnknownHostKeyError
	if !errors.As(err, &unknown) {
		t.Fatalf("expected UnknownHostKeyError, got %v", err)
	}
	if unknown.Fingerprint != fp {
		t.Fatalf("fingerprint %q, want %q", unknown.Fingerprint, fp)
	}
}

func TestSFTPNeverSendsPrivateKeyAsPassword(t *testing.T) {
	addr, fp := startSFTPServer(t)
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	block, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatal(err)
	}
	// A key pasted from a file often arrives with leading whitespace.
	secret := "\n" + string(pem.EncodeToMemory(block))
	seenMu.Lock()
	seenPasswords = nil
	seenMu.Unlock()

	client := replication.NewSFTPClient(addr, sftpUser, secret, t.TempDir(), fp)
	_ = client.TestConnection(context.Background()) // auth fails: server has no pubkey callback
	seenMu.Lock()
	defer seenMu.Unlock()
	for _, pw := range seenPasswords {
		if strings.Contains(pw, "PRIVATE KEY") {
			t.Fatal("private key was offered to the server as a password")
		}
	}
}

// stalledListener accepts connections and never writes.
func stalledListener(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			t.Cleanup(func() { c.Close() })
		}
	}()
	return ln.Addr().String()
}

func TestSFTPStalledServerReturnsWithinBudget(t *testing.T) {
	client := replication.NewSFTPClient(stalledListener(t), sftpUser, sftpPass, "/x", "SHA256:x")
	client.Timeout = 2 * time.Second
	start := time.Now()
	err := client.Put(context.Background(), "a.kycap", strings.NewReader("x"))
	if err == nil {
		t.Fatal("expected an error from a stalled server")
	}
	if time.Since(start) > 10*time.Second {
		t.Fatalf("took %s, budget was 2s", time.Since(start))
	}
}

func TestRelativeSFTPUsesSameAccountDirectory(t *testing.T) {
	root := t.TempDir()
	addr, fp := startSFTPServer(t, root)
	database, mgr, id := newCapsuleFixture(t)
	target := sftpTarget(addr, fp, "vault")
	if err := database.InsertReplicationTarget(t.Context(), target); err != nil {
		t.Fatal(err)
	}
	if err := mgr.TestTarget(t.Context(), target); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if _, err := mgr.SyncCapsule(t.Context(), id, target.ID); err != nil {
			t.Fatal(err)
		}
	}
	data, err := os.ReadFile(filepath.Join(root, "vault", id+".kycap"))
	if err != nil || string(data) != "mock-encrypted-capsule-content" {
		t.Fatalf("wrong relative destination: %v", err)
	}
}

func TestInterruptedAbsoluteSFTPPreservesReplica(t *testing.T) {
	root := t.TempDir()
	addr, fp := startSFTPServer(t)
	client := replication.NewSFTPClient(addr, sftpUser, sftpPass, root, fp)
	if err := client.Put(t.Context(), "cap-one.kycap", strings.NewReader("complete")); err != nil {
		t.Fatal(err)
	}
	if err := client.Put(t.Context(), "cap-one.kycap", failingSFTPReader{}); err == nil {
		t.Fatal("interrupted transfer accepted")
	}
	data, err := os.ReadFile(filepath.Join(root, "cap-one.kycap"))
	if err != nil || string(data) != "complete" {
		t.Fatal("old replica lost")
	}
	entries, err := os.ReadDir(root)
	if err != nil || len(entries) != 1 {
		t.Fatal("staging file leaked")
	}
}

type failingSFTPReader struct{}

func (failingSFTPReader) Read([]byte) (int, error) { return 0, errors.New("interrupted fixture") }

func TestSFTPStagingReaped(t *testing.T) {
	for _, testConnection := range []bool{false, true} {
		t.Run(fmt.Sprint(testConnection), func(t *testing.T) {
			root := t.TempDir()
			addr, fp := startSFTPServer(t)
			client := replication.NewSFTPClient(addr, sftpUser, sftpPass, root, fp)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			err := client.Put(ctx, "cap-one.kycap", &cancelingSFTPReader{cancel: cancel})
			if err == nil {
				t.Fatal("canceled transfer succeeded")
			}
			entries, err := os.ReadDir(root)
			if err != nil {
				t.Fatal(err)
			}
			orphan := ""
			for _, entry := range entries {
				if strings.HasPrefix(entry.Name(), ".ky-offsite-compat-") {
					orphan = filepath.Join(root, entry.Name())
				}
			}
			if orphan == "" {
				t.Fatal("fixture did not leave an orphan on the closed session")
			}
			old := time.Now().Add(-time.Hour)
			if err := os.Chtimes(orphan, old, old); err != nil {
				t.Fatal(err)
			}
			recent := filepath.Join(root, ".ky-offsite-compat-recent")
			unrelated := filepath.Join(root, "unrelated")
			for _, name := range []string{recent, unrelated} {
				if err := os.WriteFile(name, []byte("keep"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if testConnection {
				err = client.TestConnection(t.Context())
			} else {
				err = client.Put(t.Context(), "cap-one.kycap", strings.NewReader("complete"))
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, err := os.Stat(orphan); !os.IsNotExist(err) {
				t.Fatalf("orphan not reaped: %v", err)
			}
			for _, name := range []string{recent, unrelated} {
				if _, err := os.Stat(name); err != nil {
					t.Fatal("live or unrelated file removed")
				}
			}
		})
	}
}

type cancelingSFTPReader struct {
	cancel context.CancelFunc
	sent   bool
}

func (r *cancelingSFTPReader) Read(p []byte) (int, error) {
	if !r.sent {
		r.sent = true
		return copy(p, "partial"), nil
	}
	r.cancel()
	// Allow the registered cancellation callback to close the network session,
	// rather than exercising only the live-connection reader-error cleanup.
	time.Sleep(100 * time.Millisecond)
	return 0, context.Canceled
}

func TestSFTPStagingUnlistableDirectory(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses directory permissions")
	}
	root := t.TempDir()
	if err := os.Chmod(root, 0300); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(root, 0700)
	addr, fp := startSFTPServer(t)
	client := replication.NewSFTPClient(addr, sftpUser, sftpPass, root, fp)
	if err := client.TestConnection(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := client.Put(t.Context(), "cap-one.kycap", strings.NewReader("sealed")); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(root, "cap-one.kycap"))
	if err != nil || string(data) != "sealed" {
		t.Fatal("upload failed")
	}
}

// The SFTP server denies removal of an old file, as a sticky shared directory
// can, while retaining create/rename permissions. Protocol injection avoids
// requiring root/chown or immutable-file capabilities on the test machine.
func TestSFTPStagingUnremovableEntry(t *testing.T) {
	handlers := sftp.InMemHandler()
	denied := &denyStagingRemove{FileCmder: handlers.FileCmd}
	handlers.FileCmd = denied
	handlers.FileList = oldStagingList{handlers.FileList}
	addr, fp := startSFTPServerWithHandlers(t, &handlers)
	conn, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{User: sftpUser, Auth: []ssh.AuthMethod{ssh.Password(sftpPass)}, HostKeyCallback: ssh.InsecureIgnoreHostKey()})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	remote, err := sftp.NewClient(conn)
	if err != nil {
		t.Fatal(err)
	}
	defer remote.Close()
	if err := remote.MkdirAll("/vault"); err != nil {
		t.Fatal(err)
	}
	f, err := remote.Create("/vault/.ky-offsite-compat-stale")
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	client := replication.NewSFTPClient(addr, sftpUser, sftpPass, "/vault", fp)
	if err := client.TestConnection(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := client.Put(t.Context(), "cap-one.kycap", strings.NewReader("sealed")); err != nil {
		t.Fatal(err)
	}
	result, err := remote.Open("/vault/cap-one.kycap")
	if err != nil {
		t.Fatal(err)
	}
	defer result.Close()
	data, err := io.ReadAll(result)
	if err != nil || string(data) != "sealed" {
		t.Fatal("upload failed")
	}
	denied.mu.Lock()
	attempts := denied.attempts
	denied.mu.Unlock()
	if attempts != 2 {
		t.Fatalf("expected two denied cleanup attempts, got %d", attempts)
	}
}

type denyStagingRemove struct {
	sftp.FileCmder
	mu       sync.Mutex
	attempts int
}

func (d *denyStagingRemove) Filecmd(r *sftp.Request) error {
	if r.Method == "Remove" && strings.Contains(r.Filepath, ".ky-offsite-compat-") {
		d.mu.Lock()
		d.attempts++
		d.mu.Unlock()
		return os.ErrPermission
	}
	return d.FileCmder.Filecmd(r)
}

type oldStagingList struct{ sftp.FileLister }

func (l oldStagingList) Filelist(r *sftp.Request) (sftp.ListerAt, error) {
	base, err := l.FileLister.Filelist(r)
	return agedStaging{base}, err
}

type agedStaging struct{ sftp.ListerAt }

func (l agedStaging) ListAt(dst []os.FileInfo, offset int64) (int, error) {
	n, err := l.ListerAt.ListAt(dst, offset)
	for i := 0; i < n; i++ {
		if strings.HasPrefix(dst[i].Name(), ".ky-offsite-compat-") {
			dst[i] = oldStagingInfo{dst[i]}
		}
	}
	return n, err
}

type oldStagingInfo struct{ os.FileInfo }

func (oldStagingInfo) ModTime() time.Time { return time.Now().Add(-time.Hour) }
