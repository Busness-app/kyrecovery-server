package ceremony_test

import (
	"bytes"
	"testing"
	"time"

	"github.com/Busness-app/kyrecovery-server/internal/ceremony"
	"github.com/Busness-app/kyrecovery-server/internal/crypto"
)

func TestQuorumCeremonyWorkflow(t *testing.T) {
	mgr := ceremony.NewManager()

	masterKey, err := crypto.GenerateMasterKey()
	if err != nil {
		t.Fatalf("GenerateMasterKey failed: %v", err)
	}

	shares, err := crypto.Split(masterKey, 2, 3)
	if err != nil {
		t.Fatalf("Split failed: %v", err)
	}

	// 1. Create ceremony
	sess, err := mgr.CreateSession("cap-test-01", "kysignon", "Quarterly Drill", "Alice Admin", 2, 3, 10*time.Minute)
	if err != nil {
		t.Fatalf("CreateSession failed: %v", err)
	}
	if sess.Status != ceremony.StatusGathering || sess.SubmittedCount != 0 {
		t.Fatalf("unexpected session state: %+v", sess)
	}

	// 2. Submit Share 1 from Custodian Bob
	sess, err = mgr.SubmitShare(sess.ID, "Bob Keyholder", shares[0].String())
	if err != nil {
		t.Fatalf("SubmitShare 1 failed: %v", err)
	}
	if sess.Status != ceremony.StatusGathering || sess.SubmittedCount != 1 {
		t.Fatalf("expected gathering with count 1, got %+v", sess)
	}

	// 3. Attempt to reconstruct before quorum (should fail)
	_, err = mgr.GetReconstructedKey(sess.ID)
	if err == nil {
		t.Fatalf("expected error when reconstructing before quorum")
	}

	// 4. Submit duplicate share index (should fail)
	_, err = mgr.SubmitShare(sess.ID, "Bob Again", shares[0].String())
	if err == nil {
		t.Fatalf("expected error submitting duplicate share index")
	}

	// 5. Submit Share 2 from Custodian Charlie (Quorum reached!)
	sess, err = mgr.SubmitShare(sess.ID, "Charlie Keyholder", shares[1].String())
	if err != nil {
		t.Fatalf("SubmitShare 2 failed: %v", err)
	}
	if sess.Status != ceremony.StatusQuorumReached || sess.SubmittedCount != 2 {
		t.Fatalf("expected quorum_reached with count 2, got %+v", sess)
	}

	// 6. Reconstruct key
	reconstructed, err := mgr.GetReconstructedKey(sess.ID)
	if err != nil {
		t.Fatalf("GetReconstructedKey failed: %v", err)
	}
	if !bytes.Equal(reconstructed, masterKey) {
		t.Fatalf("reconstructed key mismatch against original master key")
	}

	// 7. Complete session (should wipe in-memory shares)
	if err := mgr.CompleteSession(sess.ID); err != nil {
		t.Fatalf("CompleteSession failed: %v", err)
	}

	completedSess, _ := mgr.GetSession(sess.ID)
	if completedSess.Status != ceremony.StatusExecuted {
		t.Fatalf("expected executed status, got %s", completedSess.Status)
	}
}
