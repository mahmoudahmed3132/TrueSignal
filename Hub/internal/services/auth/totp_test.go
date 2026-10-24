package auth

import (
	"net/url"
	"strings"
	"testing"
	"time"
)

// RFC 6238 Appendix B, SHA-1 seed "12345678901234567890", truncated to the
// last 6 of the 8 published digits.
func TestHOTPMatchesRFC6238Vectors(t *testing.T) {
	key := []byte("12345678901234567890")
	for _, v := range []struct {
		unix int64
		want string
	}{
		{59, "287082"},
		{1111111109, "081804"},
		{1111111111, "050471"},
		{1234567890, "005924"},
		{2000000000, "279037"},
		{20000000000, "353130"},
	} {
		if got := hotp(key, uint64(v.unix/totpPeriod)); got != v.want {
			t.Errorf("t=%d: got %s, want %s", v.unix, got, v.want)
		}
	}
}

func TestVerifyTOTPWindowAndReplay(t *testing.T) {
	secret := b32.EncodeToString([]byte("12345678901234567890"))
	now := time.Unix(1111111111, 0)
	step := now.Unix() / totpPeriod
	code := hotp([]byte("12345678901234567890"), uint64(step))

	got, ok := verifyTOTP(secret, code, now, 0)
	if !ok || got != step {
		t.Fatalf("current code rejected: %v %d", ok, got)
	}
	if _, ok := verifyTOTP(secret, code, now, step); ok {
		t.Fatal("replayed code accepted")
	}
	// One step of skew either side is accepted, two are not.
	if _, ok := verifyTOTP(secret, code, now.Add(totpPeriod*time.Second), 0); !ok {
		t.Fatal("code from previous step rejected")
	}
	if _, ok := verifyTOTP(secret, code, now.Add(2*totpPeriod*time.Second), 0); ok {
		t.Fatal("code two steps old accepted")
	}
	// Lower-case secrets (as typed by hand) decode too.
	if _, ok := verifyTOTP(strings.ToLower(secret), code, now, 0); !ok {
		t.Fatal("lower-case secret rejected")
	}
	for _, bad := range []string{"", "12345", "1234567", "abcdef"} {
		if _, ok := verifyTOTP(secret, bad, now, 0); ok {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestNewSecretAndURI(t *testing.T) {
	s, err := newTOTPSecret()
	if err != nil || len(s) != 32 {
		t.Fatalf("secret %q %v", s, err)
	}
	u, err := url.Parse(totpURI(s, "TrueSignal", "admin@hub.example"))
	if err != nil || u.Scheme != "otpauth" || u.Host != "totp" || u.Query().Get("secret") != s || u.Query().Get("issuer") != "TrueSignal" {
		t.Fatalf("uri %v %v", u, err)
	}
	if u.Path != "/TrueSignal:admin@hub.example" {
		t.Fatalf("label %q", u.Path)
	}
}
