package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// TOTP per RFC 6238 with the parameters every authenticator app supports:
// HMAC-SHA1, 6 digits, 30-second steps. One step of clock skew is accepted
// either side.
const (
	totpDigits = 6
	totpPeriod = 30
	totpSkew   = 1
)

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// newTOTPSecret returns a random 160-bit secret, base32-encoded (RFC 4226
// recommends at least 128 bits; 160 matches the HMAC-SHA1 block output).
func newTOTPSecret() (string, error) {
	key := make([]byte, 20)
	if _, err := rand.Read(key); err != nil {
		return "", err
	}
	return b32.EncodeToString(key), nil
}

// totpURI is the otpauth:// URI authenticator apps import from a QR code.
func totpURI(secret, issuer, account string) string {
	label := url.PathEscape(issuer + ":" + account)
	q := url.Values{}
	q.Set("secret", secret)
	q.Set("issuer", issuer)
	q.Set("algorithm", "SHA1")
	q.Set("digits", fmt.Sprint(totpDigits))
	q.Set("period", fmt.Sprint(totpPeriod))
	return "otpauth://totp/" + label + "?" + q.Encode()
}

// hotp is RFC 4226 HOTP truncated to totpDigits.
func hotp(key []byte, counter uint64) string {
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], counter)
	mac := hmac.New(sha1.New, key)
	mac.Write(msg[:])
	sum := mac.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	bin := binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff
	mod := uint32(1)
	for i := 0; i < totpDigits; i++ {
		mod *= 10
	}
	return fmt.Sprintf("%0*d", totpDigits, bin%mod)
}

// verifyTOTP checks code against secret at now. It returns the matching time
// step, which must be later than lastStep: a code is accepted once, so one
// observed in transit (or shoulder-surfed) cannot be replayed.
func verifyTOTP(secret, code string, now time.Time, lastStep int64) (int64, bool) {
	if len(code) != totpDigits {
		return 0, false
	}
	key, err := b32.DecodeString(strings.ToUpper(secret))
	if err != nil || len(key) == 0 {
		return 0, false
	}
	cur := now.Unix() / totpPeriod
	var matched int64 = -1
	// Check every window without returning early, so timing does not reveal
	// which step matched.
	for d := int64(-totpSkew); d <= totpSkew; d++ {
		step := cur + d
		if step < 0 {
			continue
		}
		if subtle.ConstantTimeCompare([]byte(hotp(key, uint64(step))), []byte(code)) == 1 && step > lastStep {
			matched = step
		}
	}
	return matched, matched >= 0
}
