package replication_test

import (
	"context"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/hirochachacha/go-smb2"

	"github.com/Busness-app/kyrecovery-server/internal/db"
	"github.com/Busness-app/kyrecovery-server/internal/replication"
)

// SMB has no in-process server in Go, so this runs only when CI (or a
// developer) points it at a real share:
//
//	KYRECOVERY_SMB_TEST="host:port/share|user|password"
func smbTestTarget(t *testing.T) db.ReplicationTargetRecord {
	t.Helper()
	spec := os.Getenv("KYRECOVERY_SMB_TEST")
	if spec == "" {
		t.Skip("KYRECOVERY_SMB_TEST not set")
	}
	parts := strings.SplitN(spec, "|", 3)
	addrShare := strings.SplitN(parts[0], "/", 2)
	if len(parts) != 3 || len(addrShare) != 2 {
		t.Fatalf("KYRECOVERY_SMB_TEST must be host:port/share|user|password, got %q", spec)
	}
	return db.ReplicationTargetRecord{
		ID: "target-smb-01", Name: "SMB Vault", Type: "smb",
		Endpoint: addrShare[0], Bucket: addrShare[1], AccessKey: parts[1], SecretKey: parts[2],
		Prefix: "kyrecovery-test/", AutoSync: true, Status: "active", CreatedAt: time.Now().UTC(),
	}
}

func TestSMBReplication(t *testing.T) {
	ctx := context.Background()
	target := smbTestTarget(t)
	database, mgr, capID := newCapsuleFixture(t)
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

	// Read it back over SMB independently of the client under test.
	d := &smb2.Dialer{Initiator: &smb2.NTLMInitiator{User: target.AccessKey, Password: target.SecretKey}}
	conn, err := net.Dial("tcp", target.Endpoint)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	sess, err := d.Dial(conn)
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Logoff()
	share, err := sess.Mount(target.Bucket)
	if err != nil {
		t.Fatal(err)
	}
	defer share.Umount()
	data, err := share.ReadFile("kyrecovery-test/" + capID + ".kycap")
	if err != nil || string(data) != "mock-encrypted-capsule-content" {
		t.Fatalf("replicated file mismatch or missing: %v", err)
	}
}

func TestSMBRejectsBadPassword(t *testing.T) {
	target := smbTestTarget(t)
	target.SecretKey = "wrong-" + target.SecretKey
	_, mgr, _ := newCapsuleFixture(t)
	if err := mgr.TestTarget(context.Background(), target); err == nil {
		t.Fatal("TestTarget accepted a bad password")
	}
}

func TestSMBStalledServerReturnsWithinBudget(t *testing.T) {
	client := replication.NewSMBClient(stalledListener(t), "vault", "ky", "pw", "dir")
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
