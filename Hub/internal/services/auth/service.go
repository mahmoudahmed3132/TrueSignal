package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"log"
	"strings"
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
	UpdateConfigValue(key, value string) error
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
	// RequireMFA (TS_REQUIRE_MFA) forces MFA: a login without MFA enrolled
	// gets a session that can only enroll, and MFA cannot be disabled.
	RequireMFA bool
}

type session struct {
	expires    time.Time
	lastSeen   time.Time
	enrollOnly bool // may only reach the MFA enrollment endpoints
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

	// MFA (mfa.go)
	mfaMu          sync.Mutex
	pending        *pendingEnrollment
	mfaFailures    int
	mfaLockedUntil time.Time
}

func NewService(store Store, dashboardPassword string, policy ...SessionPolicy) *Service {
	p := SessionPolicy{TTL: DefaultSessionTTL, Idle: DefaultSessionIdle}
	if len(policy) > 0 {
		if policy[0].TTL > 0 {
			p.TTL = policy[0].TTL
		}
		p.Idle = policy[0].Idle
		p.RequireMFA = policy[0].RequireMFA
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
	return s.createSession(false)
}

func (s *Service) createSession(enrollOnly bool) (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	token := hex.EncodeToString(bytes)

	now := time.Now()
	s.sessionMu.Lock()
	s.sessions[token] = &session{expires: now.Add(s.policy.TTL), lastSeen: now, enrollOnly: enrollOnly}
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

// Login authenticates with the password alone; it fails with
// ErrMFARequired once MFA is enrolled.
func (s *Service) Login(password, ip string) (string, error) {
	token, _, err := s.LoginMFA(password, "", ip)
	return token, err
}

// LoginMFA checks the password, then the second factor when MFA is enrolled.
// A correct password without a code returns ErrMFARequired and does not count
// as a failure (the UI asks for the code in a second step); a wrong password
// or wrong code counts towards the per-IP lockout. enrollOnly is true when
// TS_REQUIRE_MFA is on and no MFA is enrolled yet: the session may only
// enroll.
func (s *Service) LoginMFA(password, code, ip string) (token string, enrollOnly bool, err error) {
	if s.ipLocked(ip) {
		return "", false, ErrTooManyRequests
	}
	if !s.passwordOK(password) {
		s.recordFailure(ip)
		return "", false, ErrInvalidPassword
	}
	if s.MFAEnabled() {
		if strings.TrimSpace(code) == "" {
			return "", false, ErrMFARequired
		}
		if err := s.checkSecondFactor(code); err != nil {
			s.recordFailure(ip)
			return "", false, err
		}
	} else if s.policy.RequireMFA {
		enrollOnly = true
	}
	s.clearFailures(ip)
	token, err = s.createSession(enrollOnly)
	return token, enrollOnly, err
}

func (s *Service) passwordOK(password string) bool {
	if s.dashboardPassword != "" {
		return subtle.ConstantTimeCompare([]byte(password), []byte(s.dashboardPassword)) == 1
	}
	dbHash, err := s.store.GetConfigValue("admin_hash")
	if err != nil {
		return false
	}
	return bcrypt.CompareHashAndPassword([]byte(dbHash), []byte(password)) == nil
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
