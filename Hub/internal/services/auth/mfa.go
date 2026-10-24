package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"log"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Admin MFA: TOTP (totp.go) plus single-use recovery codes. State lives in
// the config table so it survives restarts; a factory reset (which wipes the
// config table and the admin account) clears it with everything else.
const (
	mfaSecretKey   = "mfa_secret"
	mfaRecoveryKey = "mfa_recovery_codes" // comma-separated sha256 hex of each code
	mfaLastStepKey = "mfa_last_step"
	// MFAResetKey is set by the `mfa-reset` break-glass command so the Hub
	// can audit the reset on its next start.
	MFAResetKey = "mfa_reset_at"

	recoveryCodeCount = 10
	enrollmentTTL     = 10 * time.Minute
	// Account-wide limit on wrong second factors, on top of the per-IP
	// lockout: 10 wrong codes from any mix of sources lock MFA for 15 min.
	mfaMaxFailures = 10
	mfaLockout     = 15 * time.Minute
)

var (
	ErrMFARequired           = errors.New("mfa_required")
	ErrInvalidCode           = errors.New("invalid_code")
	ErrTooManyRequests       = errors.New("too_many_requests")
	ErrInvalidPassword       = errors.New("invalid_password")
	ErrMFAAlreadyEnabled     = errors.New("mfa_already_enabled")
	ErrMFANotEnabled         = errors.New("mfa_not_enabled")
	ErrMFARequiredByPolicy   = errors.New("mfa_required_by_policy")
	ErrNoPendingEnrollment   = errors.New("no_pending_enrollment")
	ErrMFAEnrollmentRequired = errors.New("mfa_enrollment_required")
)

type pendingEnrollment struct {
	secret  string
	token   string // the session that started it; only it may confirm
	expires time.Time
}

// MFAStatus is what the dashboard shows.
type MFAStatus struct {
	Enabled                bool `json:"enabled"`
	Required               bool `json:"required"`
	RecoveryCodesRemaining int  `json:"recoveryCodesRemaining"`
	EnrollmentRequired     bool `json:"enrollmentRequired"`
}

// Enrollment is returned when enrollment starts.
type Enrollment struct {
	Secret string
	URI    string
}

func (s *Service) mfaSecret() string {
	v, err := s.store.GetConfigValue(mfaSecretKey)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(v)
}

// MFAEnabled reports whether a TOTP secret is enrolled.
func (s *Service) MFAEnabled() bool { return s.mfaSecret() != "" }

func (s *Service) recoveryHashes() []string {
	v, err := s.store.GetConfigValue(mfaRecoveryKey)
	if err != nil || strings.TrimSpace(v) == "" {
		return nil
	}
	return strings.Split(v, ",")
}

func (s *Service) Status(token string) MFAStatus {
	return MFAStatus{
		Enabled:                s.MFAEnabled(),
		Required:               s.policy.RequireMFA,
		RecoveryCodesRemaining: len(s.recoveryHashes()),
		EnrollmentRequired:     s.EnrollmentPending(token),
	}
}

// --- IP lockout helpers (shared by login and MFA management) ---

func (s *Service) ipLocked(ip string) bool {
	s.authMutex.Lock()
	defer s.authMutex.Unlock()
	if state, ok := s.authTracker[ip]; ok && state.attempts >= 10 {
		if time.Now().Before(state.lockedUntil) {
			return true
		}
		delete(s.authTracker, ip)
	}
	return false
}

func (s *Service) recordFailure(ip string) {
	s.authMutex.Lock()
	defer s.authMutex.Unlock()
	st, ok := s.authTracker[ip]
	if !ok {
		st = &loginState{}
		s.authTracker[ip] = st
	}
	st.attempts++
	if st.attempts >= 10 {
		st.lockedUntil = time.Now().Add(15 * time.Minute)
		log.Printf("[!] AUDIT: IP %s locked out of dashboard for 15 minutes due to brute-force", ip)
	}
}

func (s *Service) clearFailures(ip string) {
	s.authMutex.Lock()
	delete(s.authTracker, ip)
	s.authMutex.Unlock()
}

// reauth re-checks the admin password for a sensitive MFA change, under the
// same per-IP lockout as login, so a stolen session cannot brute-force it.
func (s *Service) reauth(password, ip string) error {
	if s.ipLocked(ip) {
		return ErrTooManyRequests
	}
	if !s.passwordOK(password) {
		s.recordFailure(ip)
		return ErrInvalidPassword
	}
	return nil
}

// --- Second-factor check ---

func normalizeCode(code string) string {
	code = strings.ToLower(strings.TrimSpace(code))
	return strings.NewReplacer(" ", "", "-", "").Replace(code)
}

func hashRecovery(code string) string {
	sum := sha256.Sum256([]byte("truesignal-recovery:" + normalizeCode(code)))
	return hex.EncodeToString(sum[:])
}

// checkSecondFactor accepts a current TOTP code or an unused recovery code.
// Callers hold no locks.
func (s *Service) checkSecondFactor(code string) error {
	s.mfaMu.Lock()
	defer s.mfaMu.Unlock()
	now := time.Now()
	if now.Before(s.mfaLockedUntil) {
		return ErrTooManyRequests
	}
	code = normalizeCode(code)
	if s.verifyTOTPLocked(code, now) || s.consumeRecoveryLocked(code) {
		s.mfaFailures = 0
		return nil
	}
	s.mfaFailures++
	if s.mfaFailures >= mfaMaxFailures {
		s.mfaLockedUntil = now.Add(mfaLockout)
		s.mfaFailures = 0
		log.Printf("[!] AUDIT: %d wrong MFA codes; MFA locked for %s", mfaMaxFailures, mfaLockout)
	}
	return ErrInvalidCode
}

func (s *Service) verifyTOTPLocked(code string, now time.Time) bool {
	secret := s.mfaSecret()
	if secret == "" {
		return false
	}
	var last int64
	if v, err := s.store.GetConfigValue(mfaLastStepKey); err == nil {
		last, _ = strconv.ParseInt(strings.TrimSpace(v), 10, 64)
	}
	step, ok := verifyTOTP(secret, code, now, last)
	if !ok {
		return false
	}
	if err := s.store.UpdateConfigValue(mfaLastStepKey, strconv.FormatInt(step, 10)); err != nil {
		// Without the replay marker the code could be reused; refuse it.
		log.Printf("[ERROR] MFA: could not record used time step: %v", err)
		return false
	}
	return true
}

func (s *Service) consumeRecoveryLocked(code string) bool {
	if len(code) != 10 {
		return false
	}
	want := hashRecovery(code)
	hashes := s.recoveryHashes()
	for i, h := range hashes {
		if subtle.ConstantTimeCompare([]byte(h), []byte(want)) == 1 {
			rest := append(append([]string{}, hashes[:i]...), hashes[i+1:]...)
			if err := s.store.UpdateConfigValue(mfaRecoveryKey, strings.Join(rest, ",")); err != nil {
				log.Printf("[ERROR] MFA: could not consume recovery code: %v", err)
				return false
			}
			log.Printf("[!] AUDIT: MFA recovery code used; %d remaining", len(rest))
			return true
		}
	}
	return false
}

// newRecoveryCodes returns fresh codes (shown once) and stores their hashes.
func (s *Service) newRecoveryCodes() ([]string, error) {
	codes := make([]string, recoveryCodeCount)
	hashes := make([]string, recoveryCodeCount)
	for i := range codes {
		raw := make([]byte, 7)
		if _, err := rand.Read(raw); err != nil {
			return nil, err
		}
		c := strings.ToLower(b32.EncodeToString(raw))[:10] // 50 bits
		codes[i] = c[:5] + "-" + c[5:]
		hashes[i] = hashRecovery(c)
	}
	if err := s.store.UpdateConfigValue(mfaRecoveryKey, strings.Join(hashes, ",")); err != nil {
		return nil, err
	}
	return codes, nil
}

// --- Enrollment and management ---

// BeginEnrollment re-checks the password and returns a new secret. It is
// not active until ConfirmEnrollment proves the authenticator has it.
func (s *Service) BeginEnrollment(token, password, ip string) (Enrollment, error) {
	if err := s.reauth(password, ip); err != nil {
		return Enrollment{}, err
	}
	if s.MFAEnabled() {
		return Enrollment{}, ErrMFAAlreadyEnabled
	}
	secret, err := newTOTPSecret()
	if err != nil {
		return Enrollment{}, err
	}
	s.mfaMu.Lock()
	s.pending = &pendingEnrollment{secret: secret, token: token, expires: time.Now().Add(enrollmentTTL)}
	s.mfaMu.Unlock()
	return Enrollment{Secret: secret, URI: totpURI(secret, "TrueSignal", s.accountLabel())}, nil
}

func (s *Service) accountLabel() string {
	if v, err := s.store.GetConfigValue("hub_endpoint"); err == nil {
		if u, err := url.Parse(strings.TrimSpace(v)); err == nil && u.Hostname() != "" {
			return "admin@" + u.Hostname()
		}
	}
	return "admin"
}

// ConfirmEnrollment activates the pending secret when code matches it and
// returns the recovery codes (shown once). It lifts the enrollment-only
// restriction on the calling session.
func (s *Service) ConfirmEnrollment(token, code string) ([]string, error) {
	s.mfaMu.Lock()
	p := s.pending
	if p == nil || p.token != token || time.Now().After(p.expires) {
		s.mfaMu.Unlock()
		return nil, ErrNoPendingEnrollment
	}
	step, ok := verifyTOTP(p.secret, normalizeCode(code), time.Now(), 0)
	if !ok {
		s.mfaMu.Unlock()
		return nil, ErrInvalidCode
	}
	s.pending = nil
	s.mfaMu.Unlock()

	codes, err := s.newRecoveryCodes()
	if err != nil {
		return nil, err
	}
	if err := s.store.UpdateConfigValue(mfaLastStepKey, strconv.FormatInt(step, 10)); err != nil {
		return nil, err
	}
	if err := s.store.UpdateConfigValue(mfaSecretKey, p.secret); err != nil {
		return nil, err
	}
	s.sessionMu.Lock()
	if sess, ok := s.sessions[token]; ok {
		sess.enrollOnly = false
	}
	s.sessionMu.Unlock()
	log.Println("[!] AUDIT: admin MFA enabled")
	return codes, nil
}

// DisableMFA needs the password and a current code (or recovery code). It is
// refused while TS_REQUIRE_MFA is on.
func (s *Service) DisableMFA(password, code, ip string) error {
	if s.policy.RequireMFA {
		return ErrMFARequiredByPolicy
	}
	if err := s.reauth(password, ip); err != nil {
		return err
	}
	if !s.MFAEnabled() {
		return ErrMFANotEnabled
	}
	if err := s.checkSecondFactor(code); err != nil {
		s.recordFailure(ip)
		return err
	}
	if err := ClearMFA(s.store); err != nil {
		return err
	}
	log.Println("[!] AUDIT: admin MFA disabled")
	return nil
}

// RegenerateRecoveryCodes replaces all recovery codes.
func (s *Service) RegenerateRecoveryCodes(password, code, ip string) ([]string, error) {
	if err := s.reauth(password, ip); err != nil {
		return nil, err
	}
	if !s.MFAEnabled() {
		return nil, ErrMFANotEnabled
	}
	if err := s.checkSecondFactor(code); err != nil {
		s.recordFailure(ip)
		return nil, err
	}
	codes, err := s.newRecoveryCodes()
	if err == nil {
		log.Println("[!] AUDIT: admin MFA recovery codes regenerated")
	}
	return codes, err
}

// ConfigWriter is the store slice ClearMFA needs.
type ConfigWriter interface {
	UpdateConfigValue(key, value string) error
}

// ClearMFA removes the enrolled secret and recovery codes. Used by DisableMFA
// and by the `mfa-reset` break-glass command.
func ClearMFA(w ConfigWriter) error {
	for _, k := range []string{mfaSecretKey, mfaRecoveryKey, mfaLastStepKey} {
		if err := w.UpdateConfigValue(k, ""); err != nil {
			return err
		}
	}
	return nil
}

// EnrollmentPending reports whether the session may only enroll MFA
// (TS_REQUIRE_MFA with no MFA enrolled at login).
func (s *Service) EnrollmentPending(token string) bool {
	s.sessionMu.Lock()
	defer s.sessionMu.Unlock()
	sess, ok := s.sessions[token]
	return ok && sess.enrollOnly
}
