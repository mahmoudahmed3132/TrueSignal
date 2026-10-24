// Package honeytoken links lures to logins. The Hub plants a fabricated
// credential in each File Canary instance's lures and recognises it when an
// attacker later tries it against any service decoy in the fleet.
//
// Passwords are compared by keyed HMAC: the Hub owns one fleet capture key
// (config capture_hash_key) and hands it to every decoy that hashes captured
// passwords (TS_CAPTURE_HASH_KEY), so a decoy's password_hmac for a planted
// secret equals the honeytoken's secret_hmac. Usernames are compared in
// plaintext, which also covers NTLM and RDP captures that carry no password.
package honeytoken

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"time"

	"github.com/truesignal/hub/internal/models"
)

// Trigger is the event raised when a honeytoken is used.
const Trigger = "honeytoken_used"

const captureKeyConfig = "capture_hash_key"

type Store interface {
	GetConfigValue(key string) (string, error)
	UpdateConfigValue(key, value string) error
	GetHoneytoken(nodeID, sensorID string) (*models.Honeytoken, error)
	InsertHoneytoken(h models.Honeytoken) error
	FindHoneytokens(usernames, hmacs []string) ([]models.Honeytoken, error)
	RecordHoneytokenUse(id, ts string) error
	ListHoneytokens() ([]models.Honeytoken, error)
}

type Service struct {
	store Store
	mu    sync.Mutex
}

func NewService(store Store) *Service {
	return &Service{store: store}
}

// CaptureKey returns the fleet capture key, creating it on first use. It is
// read from the store every time, so a factory reset (which wipes config)
// yields a fresh key rather than a stale cached one.
func (s *Service) CaptureKey() (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.captureKeyLocked()
}

func (s *Service) captureKeyLocked() (string, error) {
	key, err := s.store.GetConfigValue(captureKeyConfig)
	if err == nil && key != "" {
		return key, nil
	}
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	key = hex.EncodeToString(b)
	if err := s.store.UpdateConfigValue(captureKeyConfig, key); err != nil {
		return "", err
	}
	return key, nil
}

// hmacHex is the decoys' password HMAC: HMAC-SHA256 over the value with the
// key string's bytes (Sensors/official/*/credcapture).
func hmacHex(key, value string) string {
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write([]byte(value))
	return hex.EncodeToString(mac.Sum(nil))
}

// keyID matches the decoys' hmac_key_id, so the Hub only compares HMACs that
// were produced with the fleet key.
func keyID(key string) string {
	return hmacHex(key, "truesignal-key-id")[:8]
}

var accountWords = []string{"backup", "deploy", "sqlsync", "reports", "monitor", "etl", "build", "svcdesk"}

func randomString(alphabet string, n int) (string, error) {
	var b strings.Builder
	for i := 0; i < n; i++ {
		idx, err := rand.Int(rand.Reader, big.NewInt(int64(len(alphabet))))
		if err != nil {
			return "", err
		}
		b.WriteByte(alphabet[idx.Int64()])
	}
	return b.String(), nil
}

func generate() (username, secret string, err error) {
	w, err := rand.Int(rand.Reader, big.NewInt(int64(len(accountWords))))
	if err != nil {
		return "", "", err
	}
	suffix, err := randomString("0123456789abcdef", 4)
	if err != nil {
		return "", "", err
	}
	// Distinctive enough to never collide with a real account, plausible
	// enough to be tried.
	username = "svc_" + accountWords[w.Int64()] + suffix
	body, err := randomString("ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789", 14)
	if err != nil {
		return "", "", err
	}
	tail, err := randomString("!#%*+-", 1)
	if err != nil {
		return "", "", err
	}
	return username, body + tail, nil
}

// TokenFor returns the honeytoken a File Canary instance plants, creating it
// on first use. It is stable: lures are written once, so the token must not
// change between deployments.
func (s *Service) TokenFor(nodeID, sensorID string) (models.Honeytoken, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if h, err := s.store.GetHoneytoken(nodeID, sensorID); err != nil {
		return models.Honeytoken{}, err
	} else if h != nil {
		return *h, nil
	}
	key, err := s.captureKeyLocked()
	if err != nil {
		return models.Honeytoken{}, err
	}
	var lastErr error
	for attempt := 0; attempt < 5; attempt++ {
		user, secret, err := generate()
		if err != nil {
			return models.Honeytoken{}, err
		}
		id, err := randomString("0123456789abcdef", 8)
		if err != nil {
			return models.Honeytoken{}, err
		}
		h := models.Honeytoken{
			ID:         "ht_" + id,
			Username:   user,
			Secret:     secret,
			SecretHMAC: hmacHex(key, secret),
			NodeID:     nodeID,
			SensorID:   sensorID,
			CreatedAt:  time.Now().UTC().Format(time.RFC3339),
		}
		if lastErr = s.store.InsertHoneytoken(h); lastErr == nil {
			return h, nil
		}
	}
	return models.Honeytoken{}, fmt.Errorf("creating honeytoken: %w", lastErr)
}

func (s *Service) List() ([]models.Honeytoken, error) {
	return s.store.ListHoneytokens()
}

// Match is one honeytoken found in an event.
type Match struct {
	Token     models.Honeytoken
	MatchedOn string // "username", "password" or "username+password"
}

// candidateUsernames extracts account names an event attempted. DOMAIN\user,
// user@realm and the CN/UID of a bind DN all reduce to the bare name.
func candidateUsernames(details map[string]any) []string {
	seen := map[string]bool{}
	var out []string
	add := func(v string) {
		v = strings.ToLower(strings.TrimSpace(v))
		if v != "" && len(v) <= 256 && !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	for _, k := range []string{"username", "attempted_username", "bind_dn", "anonymous_bind_dn"} {
		raw, ok := details[k].(string)
		if !ok || raw == "" {
			continue
		}
		if strings.Contains(raw, "=") {
			for _, rdn := range strings.Split(raw, ",") {
				name, val, found := strings.Cut(strings.TrimSpace(rdn), "=")
				if found && (strings.EqualFold(name, "cn") || strings.EqualFold(name, "uid")) {
					add(val)
				}
			}
			continue
		}
		name := raw
		if i := strings.LastIndex(name, `\`); i >= 0 {
			name = name[i+1:]
		}
		add(name)
		if user, _, found := strings.Cut(name, "@"); found {
			add(user)
		}
	}
	return out
}

// candidateHMACs returns password HMACs under the fleet key: hashed captures
// whose hmac_key_id is the fleet key's, and plaintext captures (plain mode)
// hashed here.
func candidateHMACs(details map[string]any, key string) []string {
	var out []string
	id, _ := details["hmac_key_id"].(string)
	for k, v := range details {
		str, ok := v.(string)
		if !ok || str == "" {
			continue
		}
		switch {
		case strings.HasSuffix(k, "password_hmac") && id == keyID(key):
			out = append(out, strings.ToLower(str))
		case k == "password" || k == "attempted_password":
			out = append(out, hmacHex(key, str))
		}
	}
	return out
}

// Match finds honeytokens used in an event. Hub-raised honeytoken events are
// never matched again.
func (s *Service) Match(e models.Event) ([]Match, error) {
	if e.EventTrigger == Trigger {
		return nil, nil
	}
	var details map[string]any
	if err := json.Unmarshal(e.Details, &details); err != nil || details == nil {
		return nil, nil
	}
	key, err := s.CaptureKey()
	if err != nil {
		return nil, err
	}
	users := candidateUsernames(details)
	hmacs := candidateHMACs(details, key)
	tokens, err := s.store.FindHoneytokens(users, hmacs)
	if err != nil || len(tokens) == 0 {
		return nil, err
	}

	userSet := map[string]bool{}
	for _, u := range users {
		userSet[u] = true
	}
	hmacSet := map[string]bool{}
	for _, h := range hmacs {
		hmacSet[h] = true
	}
	var out []Match
	for _, t := range tokens {
		var on []string
		if userSet[strings.ToLower(t.Username)] {
			on = append(on, "username")
		}
		if hmacSet[strings.ToLower(t.SecretHMAC)] {
			on = append(on, "password")
		}
		if len(on) > 0 {
			out = append(out, Match{Token: t, MatchedOn: strings.Join(on, "+")})
		}
	}
	return out, nil
}

// RecordUse notes that a honeytoken was used.
func (s *Service) RecordUse(id string) error {
	return s.store.RecordHoneytokenUse(id, time.Now().UTC().Format(time.RFC3339))
}
