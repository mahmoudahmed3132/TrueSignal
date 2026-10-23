package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"

	sdk "github.com/truesignal/sdk-go"
)

// credcapture decides how much of a captured secret leaves the decoy. It is the
// same policy the Web Router Decoy uses: "hash" (default) records a keyed
// HMAC-SHA256 and the length, never the secret; "plain" opts in to cleartext;
// "none" records only that something was submitted. A real AD password or NTLM
// hash landing in the Hub or SIEM is credential material under PCI DSS, so the
// default never stores the recoverable value.
type credcapture struct {
	mode string // "hash" | "plain" | "none"
	key  []byte
}

func newCredCapture(mode, captureKey, nodeKey string) credcapture {
	switch mode {
	case "plain", "none":
	default:
		mode = "hash"
	}
	key := []byte(captureKey)
	if len(key) == 0 {
		// Derived from the node key, which the Hub stores only as a hash, so
		// Hub/SIEM records alone cannot be dictionary-tested. Set
		// TS_CAPTURE_HASH_KEY to correlate a secret across the fleet.
		key = []byte("truesignal-capture:" + nodeKey)
	}
	return credcapture{mode: mode, key: key}
}

// password returns event details for a submitted password under the active mode.
func (c credcapture) password(password string) sdk.EventDetails {
	return c.secret("password", password)
}

// secret labels an arbitrary captured value (password, NTLM response, community
// string) under the prefix, e.g. prefix="password" -> "password_hmac".
func (c credcapture) secret(prefix, value string) sdk.EventDetails {
	switch c.mode {
	case "plain":
		return sdk.EventDetails{{Key: prefix, Value: truncate(value, 256)}}
	case "none":
		return sdk.EventDetails{{Key: prefix + "_submitted", Value: value != ""}}
	default:
		mac := hmac.New(sha256.New, c.key)
		mac.Write([]byte(value))
		return sdk.EventDetails{
			{Key: prefix + "_hmac", Value: hex.EncodeToString(mac.Sum(nil))},
			{Key: prefix + "_length", Value: len(value)},
			{Key: "hmac_key_id", Value: c.keyID()},
		}
	}
}

// keyID lets an analyst tell which key produced an HMAC without revealing it.
func (c credcapture) keyID() string {
	mac := hmac.New(sha256.New, c.key)
	mac.Write([]byte("truesignal-key-id"))
	return hex.EncodeToString(mac.Sum(nil))[:8]
}

func truncate(s string, n int) string {
	s = sanitizeUTF8(s)
	if len(s) > n {
		return s[:n]
	}
	return s
}
