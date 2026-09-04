package audit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"iter"
	"sync"
	"time"

	"github.com/Busness-app/ky-primitives/auditchain"
	"github.com/Busness-app/kyrecovery-server/internal/db"
)

// Ledger appends to the tamper-evident audit chain.
//
// Events are chained with ky-primitives/auditchain under a key held outside
// SQLite (see internal/secrets), so an attacker who can write to the database
// cannot edit an event and recompute the chain. The chain's length and head are
// stored in audit_anchor alongside it, which is what catches events removed from
// the end: what remains still links. It does not cover an attacker who holds the
// server key or the data directory — they can forge the chain and its anchor
// together. For a guarantee that survives full host compromise, anchor the chain
// head somewhere KyRecovery cannot write.
type Ledger struct {
	mu    sync.Mutex
	db    *db.DB
	key   []byte
	chain *auditchain.Chain
	err   error // set when the stored log does not match its anchor; every Record fails

	lastPoisonLog time.Time // rate-limits the refusal log; a busy server would flood
}

// NewLedger initializes an audit ledger keyed by the database's server keyring,
// resuming the chain from the stored anchor.
func NewLedger(database *db.DB) *Ledger {
	l := &Ledger{db: database}
	if database == nil {
		return l
	}
	l.key = database.Keyring().LedgerKey()
	if err := l.resume(context.Background()); err != nil {
		l.err = err
		defaultLogger.Error("ledger_resume", "system", "audit_events", "the audit chain cannot be resumed", err)
	}
	return l
}

func (l *Ledger) resume(ctx context.Context) error {
	count, hash, found, err := l.db.GetAuditAnchor(ctx)
	if err != nil {
		return err
	}
	if !found {
		// No anchor is only a fresh store if the log is empty too. Events without an
		// anchor is the same evidence as an anchor without its events: something removed
		// a row, and the row it removed is the one that would have caught it.
		last, err := l.db.GetLastAuditEvent(ctx)
		if err != nil {
			return err
		}
		if last != nil {
			return errors.New("audit log has events but no anchor; refusing to append")
		}
		l.chain, err = auditchain.New(l.key)
		return err
	}
	last, err := l.db.GetLastAuditEvent(ctx)
	if err != nil {
		return err
	}
	if last == nil || last.Seq != count || last.EventHash != hash {
		return errors.New("audit log does not match its anchor; refusing to append")
	}
	l.chain, err = auditchain.Resume(l.key, toRecord(*last), auditchain.Anchor{Count: count, Hash: hash})
	return err
}

// toRecord maps a stored row to its chain record. The field order here is the
// order every record is hashed in; changing it changes every digest.
func toRecord(ar db.AuditRecord) auditchain.Record {
	return auditchain.Record{Seq: ar.Seq, Prev: ar.PrevHash, Hash: ar.EventHash,
		Fields: []string{ar.Action, ar.Actor, ar.TargetID, ar.DetailsJSON, ar.CreatedAt}}
}

// Healthy reports why the ledger cannot append, or nil. The latch is set once in
// NewLedger and never written again, so callers read it without the lock: taking
// it would queue them behind an in-flight append.
func (l *Ledger) Healthy() error { return l.err }

// Record appends a new event to the chain and emits a structured log line.
func (l *Ledger) Record(ctx context.Context, action, actor, targetID string, details map[string]interface{}) (*db.AuditRecord, error) {
	if l.db == nil {
		return nil, nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.err != nil {
		// Every caller discards this error, so the refusal has to be audible here.
		if now := time.Now(); now.Sub(l.lastPoisonLog) > time.Minute {
			l.lastPoisonLog = now
			defaultLogger.Error(action, actor, targetID, "the audit ledger is not writable; this event was not recorded", l.err)
		}
		return nil, l.err
	}

	actor = sanitizeActor(actor)
	if details == nil {
		details = map[string]interface{}{}
	}
	dj, err := json.Marshal(details)
	if err != nil {
		return nil, err
	}
	created := time.Now().UTC().Format(time.RFC3339Nano)

	var out db.AuditRecord
	if _, err := l.chain.Append(ctx, func(r auditchain.Record, a auditchain.Anchor) error {
		out = db.AuditRecord{Seq: r.Seq, PrevHash: r.Prev, EventHash: r.Hash, Action: action, Actor: actor,
			TargetID: targetID, DetailsJSON: string(dj), CreatedAt: created}
		return l.db.InsertAuditEventAndAnchor(ctx, out, a.Count, a.Hash)
	}, action, actor, targetID, string(dj), created); err != nil {
		defaultLogger.Error(action, actor, targetID, "failed to append the audit event", err)
		return nil, fmt.Errorf("audit append: %w", err)
	}

	defaultLogger.Info(action, actor, targetID, "AUDIT_RECORDED", fmt.Sprintf("seq=%d hash=%s", out.Seq, out.EventHash[:8]))
	return &out, nil
}

// Verify streams the whole log against the anchor and returns the anchor it was
// checked against. It does not page: kyrecovery's previous verifier read a fixed
// 100000 rows and reported a gap on a healthy chain past that.
func (l *Ledger) Verify(ctx context.Context) (auditchain.Anchor, error) {
	if l.db == nil {
		return auditchain.Anchor{}, nil
	}
	// The lock is held for the whole walk: an append landing between the anchor read
	// and the last row makes a healthy chain look one record longer than its anchor.
	l.mu.Lock()
	defer l.mu.Unlock()
	count, hash, found, err := l.db.GetAuditAnchor(ctx)
	if err != nil {
		return auditchain.Anchor{}, err
	}
	anchor := auditchain.Anchor{Count: count, Hash: hash}
	if !found {
		// The package exports no genesis constant; a fresh chain is the empty anchor.
		empty, err := auditchain.New(l.key)
		if err != nil {
			return auditchain.Anchor{}, err
		}
		anchor = empty.Anchor()
	}
	records := func(yield func(auditchain.Record, error) bool) {
		for ar, err := range l.db.IterAuditEvents(ctx) {
			if !yield(toRecord(ar), err) {
				return
			}
		}
	}
	return anchor, auditchain.VerifyStream(l.key, iter.Seq2[auditchain.Record, error](records), anchor)
}
