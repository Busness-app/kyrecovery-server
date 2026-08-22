package ceremony

import (
	"testing"
	"time"

	"kyrecovery-server/internal/crypto"
)

// TestReapExpiresAndForgetsSessions proves ceremonies do not accumulate for the
// lifetime of the process, taking custodian metadata with them.
func TestReapExpiresAndForgetsSessions(t *testing.T) {
	m := NewManager()
	defer m.Close()

	sess, err := m.CreateSession("cap-1", "kysignon", "test", "ops", 2, 3, time.Minute)
	if err != nil {
		t.Fatalf("CreateSession failed: %v", err)
	}

	// Past its TTL the ceremony expires and its shares are wiped.
	m.reap(time.Now().UTC().Add(2 * time.Minute))
	got, err := m.GetSession(sess.ID)
	if err != nil {
		t.Fatalf("expired session should still be listable briefly: %v", err)
	}
	if got.Status != StatusExpired {
		t.Fatalf("expected status %q, got %q", StatusExpired, got.Status)
	}

	// After the retention window it is gone entirely.
	m.reap(time.Now().UTC().Add(2*time.Minute + terminalRetention + time.Minute))
	if _, err := m.GetSession(sess.ID); err == nil {
		t.Fatal("a finished ceremony was retained indefinitely")
	}
	if len(m.ListSessions()) != 0 {
		t.Fatal("expected no remaining sessions")
	}
}

// TestCloseWipesSessions covers server shutdown and repeated Close calls.
func TestCloseWipesSessions(t *testing.T) {
	m := NewManager()
	sess, err := m.CreateSession("cap-1", "kysignon", "test", "ops", 2, 3, time.Hour)
	if err != nil {
		t.Fatalf("CreateSession failed: %v", err)
	}

	m.Close()
	m.Close() // must be idempotent

	if _, err := m.GetSession(sess.ID); err == nil {
		t.Fatal("Close should have dropped in-flight ceremonies")
	}
}

// TestPublicViewCarriesNoShares proves the handed-out session never aliases the
// live one, so shares cannot leak and the reaper cannot mutate a response mid-encode.
func TestPublicViewCarriesNoShares(t *testing.T) {
	m := NewManager()
	defer m.Close()

	key, err := crypto.GenerateMasterKey()
	if err != nil {
		t.Fatalf("GenerateMasterKey failed: %v", err)
	}
	shares, err := crypto.Split(key, 2, 3)
	if err != nil {
		t.Fatalf("Split failed: %v", err)
	}

	sess, _ := m.CreateSession("cap-1", "kysignon", "test", "ops", 2, 3, time.Hour)
	view, err := m.SubmitShare(sess.ID, "Alice", shares[0].String())
	if err != nil {
		t.Fatalf("SubmitShare failed: %v", err)
	}
	if view.shares != nil {
		t.Fatal("the public session view still carries raw custodian shares")
	}

	// Mutating the returned copy must not corrupt the live ceremony.
	view.Participants = nil
	view.Status = StatusCancelled
	live, _ := m.GetSession(sess.ID)
	if live.Status != StatusGathering || len(live.Participants) != 1 {
		t.Fatalf("the returned session aliased manager state: %+v", live)
	}
}
