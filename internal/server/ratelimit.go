package server

import (
	"net"
	"net/http"
	"sync"
	"time"
)

// Unauthenticated pairing claims are guessable (6 digits), so attempts are capped per
// source address and per code for the lifetime of a pairing window.
const (
	claimWindow          = 15 * time.Minute
	claimAttemptsPerIP   = 10
	claimAttemptsPerCode = 5
)

// rateLimiter is a fixed-window attempt counter.
// ponytail: per-process only; move the counts to SQLite or Redis if KyRecovery is ever load-balanced.
type rateLimiter struct {
	mu     sync.Mutex
	window time.Duration
	counts map[string]*windowCount
}

type windowCount struct {
	n       int
	resetAt time.Time
}

func newRateLimiter(window time.Duration) *rateLimiter {
	return &rateLimiter{window: window, counts: make(map[string]*windowCount)}
}

// exceeded reports whether key has already used up its failure budget for this window.
func (l *rateLimiter) exceeded(key string, limit int, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	c, ok := l.counts[key]
	return ok && !now.After(c.resetAt) && c.n >= limit
}

// recordFailure charges one failed attempt to key. Successful pairings are never charged,
// so a host that legitimately pairs many services cannot lock itself out.
func (l *rateLimiter) recordFailure(key string, now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if len(l.counts) > 1024 {
		for k, c := range l.counts {
			if now.After(c.resetAt) {
				delete(l.counts, k)
			}
		}
	}

	c, ok := l.counts[key]
	if !ok || now.After(c.resetAt) {
		c = &windowCount{resetAt: now.Add(l.window)}
		l.counts[key] = c
	}
	c.n++
}

// clientIP returns the source address of r, ignoring forwarding headers a caller can forge.
// ponytail: add trusted-proxy handling only when KyRecovery is deployed behind one.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
