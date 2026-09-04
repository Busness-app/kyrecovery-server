package server

import "sync"

// idLocks serializes work on one capsule ID. A deposit holds its ID from the duplicate
// check through publish, so a concurrent identical retry waits and then sees a finished
// deposit (row and file) instead of the half of one that is in flight; a verify holds it
// so the sweep cannot read a row whose file is a moment from existing. Entries are
// refcounted and dropped at zero, so the map holds only IDs with work in progress.
type idLocks struct {
	mu sync.Mutex
	m  map[string]*idLock
}

type idLock struct {
	sync.Mutex
	refs int
}

// acquire locks id and returns its release.
func (l *idLocks) acquire(id string) func() {
	l.mu.Lock()
	if l.m == nil {
		l.m = map[string]*idLock{}
	}
	e := l.m[id]
	if e == nil {
		e = &idLock{}
		l.m[id] = e
	}
	e.refs++
	l.mu.Unlock()

	e.Lock()
	return func() {
		e.Unlock()
		l.mu.Lock()
		if e.refs--; e.refs == 0 {
			delete(l.m, id)
		}
		l.mu.Unlock()
	}
}
