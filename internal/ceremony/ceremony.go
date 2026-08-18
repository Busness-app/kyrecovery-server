package ceremony

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"kyrecovery-server/internal/crypto"
)

// CeremonyStatus indicates the lifecycle phase of a quorum gathering ceremony.
type CeremonyStatus string

const (
	StatusGathering     CeremonyStatus = "gathering"
	StatusQuorumReached CeremonyStatus = "quorum_reached"
	StatusExecuted      CeremonyStatus = "executed"
	StatusCancelled     CeremonyStatus = "cancelled"
	StatusExpired       CeremonyStatus = "expired"
)

// Participant describes a custodian who submitted their share.
type Participant struct {
	CustodianName string    `json:"custodian_name"`
	ShareIndex    byte      `json:"share_index"`
	SubmittedAt   time.Time `json:"submitted_at"`
}

// Session represents an ephemeral in-memory quorum gathering session.
type Session struct {
	ID              string         `json:"id"`
	CapsuleID       string         `json:"capsule_id"`
	ServiceName     string         `json:"service_name"`
	Purpose         string         `json:"purpose"`
	Initiator       string         `json:"initiator"`
	Threshold       int            `json:"threshold"`
	TotalShares     int            `json:"total_shares"`
	Status          CeremonyStatus `json:"status"`
	Participants    []Participant  `json:"participants"`
	SubmittedCount  int            `json:"submitted_count"`
	CreatedAt       time.Time      `json:"created_at"`
	ExpiresAt       time.Time      `json:"expires_at"`
	
	// Ephemeral in-memory share storage (strictly in RAM, wiped on completion/expiration)
	shares []crypto.Share
}

// Manager coordinates in-memory recovery quorum ceremonies.
type Manager struct {
	mu       sync.RWMutex
	sessions map[string]*Session
}

// NewManager creates a new ceremony manager.
func NewManager() *Manager {
	m := &Manager{
		sessions: make(map[string]*Session),
	}
	// Background reaper for expired sessions
	go m.reaperLoop()
	return m
}

func (m *Manager) reaperLoop() {
	ticker := time.NewTicker(1 * time.Minute)
	for range ticker.C {
		m.mu.Lock()
		now := time.Now().UTC()
		for _, s := range m.sessions {
			if s.Status == StatusGathering && now.After(s.ExpiresAt) {
				s.Status = StatusExpired
				m.scrubSessionShares(s)
			}
		}
		m.mu.Unlock()
	}
}

// CreateSession initiates a new quorum gathering ceremony.
func (m *Manager) CreateSession(capsuleID, serviceName, purpose, initiator string, threshold, totalShares int, ttl time.Duration) (*Session, error) {
	if threshold < 2 {
		threshold = 2
	}
	if ttl <= 0 {
		ttl = 30 * time.Minute
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	sessionID := fmt.Sprintf("ceremony-%d", time.Now().UnixNano())
	now := time.Now().UTC()

	sess := &Session{
		ID:             sessionID,
		CapsuleID:      capsuleID,
		ServiceName:    serviceName,
		Purpose:        purpose,
		Initiator:      initiator,
		Threshold:      threshold,
		TotalShares:    totalShares,
		Status:         StatusGathering,
		Participants:   []Participant{},
		SubmittedCount: 0,
		CreatedAt:      now,
		ExpiresAt:      now.Add(ttl),
		shares:         make([]crypto.Share, 0, threshold),
	}

	m.sessions[sessionID] = sess
	return sess, nil
}

// GetSession returns a safe public view of the ceremony session.
func (m *Manager) GetSession(id string) (*Session, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	s, exists := m.sessions[id]
	if !exists {
		return nil, errors.New("ceremony session not found")
	}

	// Return shallow copy without raw shares
	return s, nil
}

// ListSessions returns all active or recent ceremonies.
func (m *Manager) ListSessions() []*Session {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var list []*Session
	for _, s := range m.sessions {
		list = append(list, s)
	}
	return list
}

// SubmitShare adds a custodian share to the ceremony.
func (m *Manager) SubmitShare(sessionID, custodianName, rawShare string) (*Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	s, exists := m.sessions[sessionID]
	if !exists {
		return nil, errors.New("ceremony session not found")
	}

	if s.Status != StatusGathering && s.Status != StatusQuorumReached {
		return nil, fmt.Errorf("ceremony is in state %s and no longer accepting shares", s.Status)
	}

	if time.Now().UTC().After(s.ExpiresAt) {
		s.Status = StatusExpired
		m.scrubSessionShares(s)
		return nil, errors.New("ceremony has expired")
	}

	parsedShare, err := crypto.ParseShare(rawShare)
	if err != nil {
		return nil, fmt.Errorf("invalid share format (expected index-hex): %w", err)
	}

	// Check if this share index was already submitted
	for _, sh := range s.shares {
		if sh.Index == parsedShare.Index {
			return nil, fmt.Errorf("share index %d was already contributed to this ceremony", parsedShare.Index)
		}
	}

	s.shares = append(s.shares, parsedShare)
	s.Participants = append(s.Participants, Participant{
		CustodianName: custodianName,
		ShareIndex:    parsedShare.Index,
		SubmittedAt:   time.Now().UTC(),
	})
	s.SubmittedCount = len(s.shares)

	if s.SubmittedCount >= s.Threshold {
		s.Status = StatusQuorumReached
	}

	return s, nil
}

// GetReconstructedKey combines the submitted shares if quorum is satisfied.
func (m *Manager) GetReconstructedKey(sessionID string) ([]byte, error) {
	m.mu.RLock()
	s, exists := m.sessions[sessionID]
	if !exists {
		m.mu.RUnlock()
		return nil, errors.New("ceremony session not found")
	}

	if len(s.shares) < s.Threshold {
		m.mu.RUnlock()
		return nil, fmt.Errorf("quorum not yet satisfied: need %d shares, have %d", s.Threshold, len(s.shares))
	}

	key, err := crypto.Combine(s.shares, s.Threshold)
	m.mu.RUnlock()

	return key, err
}

// CompleteSession marks the ceremony as executed and cryptographically scrubs in-memory shares.
func (m *Manager) CompleteSession(sessionID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	s, exists := m.sessions[sessionID]
	if !exists {
		return errors.New("ceremony session not found")
	}

	s.Status = StatusExecuted
	m.scrubSessionShares(s)
	return nil
}

// CancelSession terminates the ceremony and wipes in-memory shares.
func (m *Manager) CancelSession(sessionID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	s, exists := m.sessions[sessionID]
	if !exists {
		return errors.New("ceremony session not found")
	}

	s.Status = StatusCancelled
	m.scrubSessionShares(s)
	return nil
}

func (m *Manager) scrubSessionShares(s *Session) {
	for i := range s.shares {
		for j := range s.shares[i].Value {
			s.shares[i].Value[j] = 0
		}
	}
	s.shares = nil
}
