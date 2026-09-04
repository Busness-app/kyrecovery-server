package replication_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"

	"github.com/Busness-app/kyrecovery-server/internal/audit"
	"github.com/Busness-app/kyrecovery-server/internal/db"
	"github.com/Busness-app/kyrecovery-server/internal/replication"
)

const sftpUser, sftpPass = "ky", "correct-horse"

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
