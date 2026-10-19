package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"log"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// --- Brute-Force Protection State ---
type loginState struct {
	attempts    int
	lockedUntil time.Time
}

type Store interface {
	GetConfigValue(key string) (string, error)
	GetNodeByKey(token string) (string, error)
}

// Session lifetime defaults. The idle timeout follows PCI DSS 8.2.8 (re-auth
// after 15 minutes of inactivity); both are overridable via SessionPolicy.
const (
	DefaultSessionTTL  = 12 * time.Hour
	DefaultSessionIdle = 15 * time.Minute
)

type SessionPolicy struct {
	TTL  time.Duration // absolute lifetime
	Idle time.Duration // inactivity timeout; 0 disables
}

type session struct {
	expires  time.Time
	lastSeen time.Time
}

type Service struct {
	store             Store
	dashboardPassword string
	policy            SessionPolicy

	// Session management
	sessionMu sync.Mutex
	sessions  map[string]*session

	// Brute-force protection
	authTracker map[string]*loginState
	authMutex   sync.Mutex

	// Node auth cache
	nodeAuthCache sync.Map
}

func NewService(store Store, dashboardPassword string, policy ...SessionPolicy) *Service {
	p := SessionPolicy{TTL: DefaultSessionTTL, Idle: DefaultSessionIdle}
	if len(policy) > 0 {
		if policy[0].TTL > 0 {
			p.TTL = policy[0].TTL
		}
		p.Idle = policy[0].Idle
	}
	return &Service{
		store:             store,
		dashboardPassword: dashboardPassword,
		policy:            p,
		sessions:          make(map[string]*session),
		authTracker:       make(map[string]*loginState),
	}
}

// SessionTTL is the absolute session lifetime (used for the cookie MaxAge).
func (s *Service) SessionTTL() time.Duration { return s.policy.TTL }

// StartWorkers starts background goroutines for cleaning up sessions and brute-force trackers.
func (s *Service) StartWorkers(ctx context.Context) {
	log.Println("[Auth] Worker started.")
	go s.cleanupSessions(ctx)
	go s.cleanupAuthTracker(ctx)
}

// --- Session Management ---

func (s *Service) cleanupSessions(ctx context.Context) {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			log.Println("[Auth] Worker stopped.")
			return
		case <-ticker.C:
			s.sessionMu.Lock()
			now := time.Now()
			for token, sess := range s.sessions {
				if s.expired(sess, now) {
					delete(s.sessions, token)
				}
			}
			s.sessionMu.Unlock()
		}
	}
}

func (s *Service) CreateSession() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	token := hex.EncodeToString(bytes)

	now := time.Now()
	s.sessionMu.Lock()
	s.sessions[token] = &session{expires: now.Add(s.policy.TTL), lastSeen: now}
	s.sessionMu.Unlock()

	return token, nil
}

func (s *Service) expired(sess *session, now time.Time) bool {
	if now.After(sess.expires) {
		return true
	}
	return s.policy.Idle > 0 && now.Sub(sess.lastSeen) > s.policy.Idle
}

// IsValid checks a session and, when valid, refreshes its idle timer.
func (s *Service) IsValid(token string) bool {
	now := time.Now()
	s.sessionMu.Lock()
	defer s.sessionMu.Unlock()

	sess, exists := s.sessions[token]
	if !exists {
		return false
	}
	if s.expired(sess, now) {
		delete(s.sessions, token)
		return false
	}
	sess.lastSeen = now
	return true
}

func (s *Service) DeleteSession(token string) {
	s.sessionMu.Lock()
	delete(s.sessions, token)
	s.sessionMu.Unlock()
}

func (s *Service) ClearAllSessions() {
	s.sessionMu.Lock()
	s.sessions = make(map[string]*session)
	s.sessionMu.Unlock()
}

// --- UI Authentication ---

func (s *Service) cleanupAuthTracker(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.authMutex.Lock()
			now := time.Now()
			for ip, state := range s.authTracker {
				if now.After(state.lockedUntil) {
					delete(s.authTracker, ip)
				}
			}
			s.authMutex.Unlock()
		}
	}
}

func (s *Service) Login(password, ip string) (string, error) {
	// Rate Limiter Pre-Check
	s.authMutex.Lock()
	if state, exists := s.authTracker[ip]; exists {
		if state.attempts >= 10 {
			if time.Now().Before(state.lockedUntil) {
				s.authMutex.Unlock()
				return "", errors.New("too_many_requests")
			}
			delete(s.authTracker, ip)
		}
	}
	s.authMutex.Unlock()

	// Evaluate Authorization
	var isAuthorized bool
	if s.dashboardPassword != "" {
		isAuthorized = subtle.ConstantTimeCompare([]byte(password), []byte(s.dashboardPassword)) == 1
	} else {
		dbHash, err := s.store.GetConfigValue("admin_hash")
		if err == nil {
			err = bcrypt.CompareHashAndPassword([]byte(dbHash), []byte(password))
			isAuthorized = (err == nil)
		}
	}

	if isAuthorized {
		s.authMutex.Lock()
		delete(s.authTracker, ip)
		s.authMutex.Unlock()
		return s.CreateSession()
	}

	// Handle Failure & Increment Rate Limiter
	s.authMutex.Lock()
	if _, exists := s.authTracker[ip]; !exists {
		s.authTracker[ip] = &loginState{}
	}
	s.authTracker[ip].attempts++
	if s.authTracker[ip].attempts >= 10 {
		s.authTracker[ip].lockedUntil = time.Now().Add(15 * time.Minute)
		log.Printf("[!] AUDIT: IP %s locked out of dashboard for 15 minutes due to brute-force", ip)
	}
	s.authMutex.Unlock()

	return "", errors.New("invalid_password")
}

// --- Node Authentication ---

func (s *Service) AuthenticateNodeRequest(token string) (string, error) {
	if token == "" {
		return "", errors.New("missing token")
	}

	cacheKey := tokenCacheKey(token)
	if cachedNodeID, ok := s.nodeAuthCache.Load(cacheKey); ok {
		return cachedNodeID.(string), nil
	}

	nodeID, err := s.store.GetNodeByKey(token)
	if err != nil || nodeID == "" {
		return "", errors.New("invalid node api key")
	}

	s.nodeAuthCache.Store(cacheKey, nodeID)
	return nodeID, nil
}

// tokenCacheKey keeps plaintext node keys out of process memory structures
// that outlive the request.
func tokenCacheKey(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// InvalidateNode evicts cached authentication for a node. It must be called
// whenever a node's key changes or the node is deleted, otherwise the old key
// keeps authenticating until the Hub restarts.
func (s *Service) InvalidateNode(nodeID string) {
	s.nodeAuthCache.Range(func(k, v any) bool {
		if v.(string) == nodeID {
			s.nodeAuthCache.Delete(k)
		}
		return true
	})
}

// ClearNodeCache evicts all cached node authentications (factory reset).
func (s *Service) ClearNodeCache() {
	s.nodeAuthCache.Range(func(k, _ any) bool {
		s.nodeAuthCache.Delete(k)
		return true
	})
}
