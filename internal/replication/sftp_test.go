package replication_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
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
func startSFTPServer(t *testing.T) (addr, fingerprint string) {
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
								srv, err := sftp.NewServer(ch)
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
		PayloadHash: "abc", Threshold: 2, TotalShares: 3, Status: "active", CreatedAt: time.Now().UTC(),
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
