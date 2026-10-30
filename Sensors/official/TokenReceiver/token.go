package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base32"
	"strings"
)

// Beacon tokens are 24 lowercase base32 characters: 10 random bytes and a
// 5-byte tag, HMAC-SHA256(key, "truesignal-beacon-v1:" || random). The Hub
// creates them; the receiver checks the tag offline with TS_BEACON_KEY, so a
// scanner guessing names under the zone raises nothing and the receiver needs
// no token list. Lowercase base32 survives DNS case randomisation (0x20) and
// fits in one label. Hub/internal/services/beacon generates the same format;
// both carry the same test vector.

const (
	tokenLen    = 24
	tokenRandom = 10
	tokenTag    = 5
	tokenDomain = "truesignal-beacon-v1:"
)

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// verifier checks beacon tokens.
type verifier struct{ key []byte }

func (v verifier) tag(random []byte) []byte {
	mac := hmac.New(sha256.New, v.key)
	mac.Write([]byte(tokenDomain))
	mac.Write(random)
	return mac.Sum(nil)[:tokenTag]
}

// valid reports whether s is a beacon token signed with the key. Case is
// ignored.
func (v verifier) valid(s string) bool {
	if len(v.key) == 0 || len(s) != tokenLen {
		return false
	}
	raw, err := b32.DecodeString(strings.ToUpper(s))
	if err != nil || len(raw) != tokenRandom+tokenTag {
		return false
	}
	return hmac.Equal(raw[tokenRandom:], v.tag(raw[:tokenRandom]))
}

// find returns the first candidate that is a valid token, lowercased.
func (v verifier) find(candidates ...string) string {
	for _, c := range candidates {
		if v.valid(c) {
			return strings.ToLower(c)
		}
	}
	return ""
}
