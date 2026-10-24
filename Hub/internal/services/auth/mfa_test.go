package auth

import (
	"strconv"
	"strings"
	"testing"
	"time"
)

func currentCode(t *testing.T, secret string, at time.Time) string {
	t.Helper()
	key, err := b32.DecodeString(secret)
	if err != nil {
		t.Fatal(err)
	}
	return hotp(key, uint64(at.Unix()/totpPeriod))
}

// enroll runs the full enrollment and returns the secret and recovery codes.
func enroll(t *testing.T, svc *Service) (string, []string) {
	t.Helper()
	tok, err := svc.CreateSession()
	if err != nil {
		t.Fatal(err)
	}
	e, err := svc.BeginEnrollment(tok, "pw-correct-horse", "10.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if svc.MFAEnabled() {
		t.Fatal("MFA active before confirmation")
	}
	codes, err := svc.ConfirmEnrollment(tok, currentCode(t, e.Secret, time.Now()))
	if err != nil || len(codes) != recoveryCodeCount {
		t.Fatalf("confirm: %v %v", codes, err)
	}
	return e.Secret, codes
}

func newMFAService(require bool) (*Service, *mockAuthStore) {
	st := &mockAuthStore{configMap: map[string]string{}}
	return NewService(st, "pw-correct-horse", SessionPolicy{RequireMFA: require}), st
}

func TestMFALoginFlow(t *testing.T) {
	svc, st := newMFAService(false)
	secret, recovery := enroll(t, svc)

	// Password alone: a second step is required, and it is not a failure.
	for i := 0; i < 15; i++ {
		if _, _, err := svc.LoginMFA("pw-correct-horse", "", "10.0.0.2"); err != ErrMFARequired {
			t.Fatalf("no code: %v", err)
		}
	}
	// Wrong password still says invalid password, not "MFA required".
	if _, _, err := svc.LoginMFA("wrong", "", "10.0.0.3"); err != ErrInvalidPassword {
		t.Fatalf("wrong password: %v", err)
	}

	// The enrollment code's step was recorded, so the same code is a replay.
	if _, _, err := svc.LoginMFA("pw-correct-horse", currentCode(t, secret, time.Now()), "10.0.0.2"); err != ErrInvalidCode {
		t.Fatalf("replayed enrollment code: %v", err)
	}
	// The next step's code works once.
	st.configMap[mfaLastStepKey] = strconv.FormatInt(time.Now().Unix()/totpPeriod-1, 10)
	code := currentCode(t, secret, time.Now())
	if tok, enrollOnly, err := svc.LoginMFA("pw-correct-horse", code, "10.0.0.2"); err != nil || tok == "" || enrollOnly {
		t.Fatalf("valid code: %v %v", enrollOnly, err)
	}
	if _, _, err := svc.LoginMFA("pw-correct-horse", code, "10.0.0.2"); err != ErrInvalidCode {
		t.Fatalf("replay: %v", err)
	}

	// Recovery codes work once, in any case and with or without the dash.
	rc := strings.ToUpper(strings.ReplaceAll(recovery[0], "-", ""))
	if _, _, err := svc.LoginMFA("pw-correct-horse", rc, "10.0.0.2"); err != nil {
		t.Fatalf("recovery code: %v", err)
	}
	if _, _, err := svc.LoginMFA("pw-correct-horse", recovery[0], "10.0.0.2"); err != ErrInvalidCode {
		t.Fatalf("reused recovery code: %v", err)
	}
	if got := svc.Status("").RecoveryCodesRemaining; got != recoveryCodeCount-1 {
		t.Fatalf("remaining %d", got)
	}
}

func TestMFAAccountLockoutAcrossIPs(t *testing.T) {
	svc, _ := newMFAService(false)
	secret, _ := enroll(t, svc)
	for i := 0; i < mfaMaxFailures; i++ {
		ip := "198.51.100." + strconv.Itoa(i) // a different source each time
		if _, _, err := svc.LoginMFA("pw-correct-horse", "000000", ip); err != ErrInvalidCode {
			t.Fatalf("attempt %d: %v", i, err)
		}
	}
	// Locked for everyone, even with a valid code from a fresh IP.
	if _, _, err := svc.LoginMFA("pw-correct-horse", currentCode(t, secret, time.Now().Add(totpPeriod*time.Second)), "203.0.113.9"); err != ErrTooManyRequests {
		t.Fatalf("after lockout: %v", err)
	}
}

func TestMFAWrongCodesCountTowardIPLockout(t *testing.T) {
	svc, _ := newMFAService(false)
	enroll(t, svc)
	for i := 0; i < 9; i++ {
		svc.LoginMFA("pw-correct-horse", "abcdefghij", "10.9.9.9") // bad recovery-length code
	}
	svc.LoginMFA("wrong", "", "10.9.9.9")
	if _, _, err := svc.LoginMFA("pw-correct-horse", "", "10.9.9.9"); err != ErrTooManyRequests {
		t.Fatalf("IP not locked: %v", err)
	}
}

func TestRequireMFAEnrollOnlySession(t *testing.T) {
	svc, _ := newMFAService(true)
	tok, enrollOnly, err := svc.LoginMFA("pw-correct-horse", "", "10.0.0.1")
	if err != nil || !enrollOnly || !svc.EnrollmentPending(tok) || !svc.Status(tok).EnrollmentRequired {
		t.Fatalf("expected enroll-only session: %v %v", enrollOnly, err)
	}
	e, err := svc.BeginEnrollment(tok, "pw-correct-horse", "10.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	// Another session cannot confirm this enrollment.
	other, _ := svc.CreateSession()
	if _, err := svc.ConfirmEnrollment(other, currentCode(t, e.Secret, time.Now())); err != ErrNoPendingEnrollment {
		t.Fatalf("foreign confirm: %v", err)
	}
	if _, err := svc.ConfirmEnrollment(tok, "000000"); err != ErrInvalidCode {
		t.Fatalf("wrong confirm code: %v", err)
	}
	if _, err := svc.ConfirmEnrollment(tok, currentCode(t, e.Secret, time.Now())); err != nil {
		t.Fatal(err)
	}
	if svc.EnrollmentPending(tok) {
		t.Fatal("restriction not lifted after enrollment")
	}
	if err := svc.DisableMFA("pw-correct-horse", "x", "10.0.0.1"); err != ErrMFARequiredByPolicy {
		t.Fatalf("disable under policy: %v", err)
	}
}

func TestEnrollmentNeedsPasswordAndDisableNeedsCode(t *testing.T) {
	svc, st := newMFAService(false)
	tok, _ := svc.CreateSession()
	if _, err := svc.BeginEnrollment(tok, "wrong", "10.0.0.1"); err != ErrInvalidPassword {
		t.Fatalf("enroll with wrong password: %v", err)
	}
	secret, _ := enroll(t, svc)
	if _, err := svc.BeginEnrollment(tok, "pw-correct-horse", "10.0.0.1"); err != ErrMFAAlreadyEnabled {
		t.Fatalf("second enrollment: %v", err)
	}
	if err := svc.DisableMFA("pw-correct-horse", "000000", "10.0.0.1"); err != ErrInvalidCode {
		t.Fatalf("disable with wrong code: %v", err)
	}
	st.configMap[mfaLastStepKey] = "0"
	if err := svc.DisableMFA("pw-correct-horse", currentCode(t, secret, time.Now()), "10.0.0.1"); err != nil {
		t.Fatal(err)
	}
	if svc.MFAEnabled() || st.configMap[mfaRecoveryKey] != "" {
		t.Fatal("MFA state not cleared")
	}
	if tok, _, err := svc.LoginMFA("pw-correct-horse", "", "10.0.0.1"); err != nil || tok == "" {
		t.Fatalf("password login after disable: %v", err)
	}
}

func TestRegenerateRecoveryCodes(t *testing.T) {
	svc, st := newMFAService(false)
	secret, old := enroll(t, svc)
	st.configMap[mfaLastStepKey] = "0"
	fresh, err := svc.RegenerateRecoveryCodes("pw-correct-horse", currentCode(t, secret, time.Now()), "10.0.0.1")
	if err != nil || len(fresh) != recoveryCodeCount {
		t.Fatal(err)
	}
	if _, _, err := svc.LoginMFA("pw-correct-horse", old[1], "10.0.0.1"); err != ErrInvalidCode {
		t.Fatalf("old recovery code still valid: %v", err)
	}
	if strings.Contains(st.configMap[mfaRecoveryKey], strings.ReplaceAll(fresh[0], "-", "")) {
		t.Fatal("recovery codes stored in clear")
	}
}
