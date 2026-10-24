// Package honeytoken links lures to logins. The Hub plants a fabricated
// credential in each File Canary instance's lures and recognises it when an
// attacker later tries it against any service decoy in the fleet.
//
// Passwords are compared by keyed HMAC. The Hub owns a master key (config
// capture_master_key) that never leaves it. Each node's password-hashing
// decoys get a key derived from it for that node only (TS_CAPTURE_HASH_KEY =
// HMAC(master, node ID)), so root on one node can at most test that node's own
// captures. The Hub re-derives the node key of each incoming event and
// compares HMACs of every honeytoken secret under it, which keeps matching
// fleet-wide. Usernames are compared in plaintext, which also covers NTLM and
// RDP captures that carry no password.
package honeytoken

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"strings"
	"sync"
	"time"

	"github.com/truesignal/hub/internal/models"
)

// Trigger is the event raised when a honeytoken is used.
const Trigger = "honeytoken_used"

const captureKeyConfig = "capture_master_key"

type Store interface {
	GetConfigValue(key string) (string, error)
	UpdateConfigValue(key, value string) error
	GetHoneytoken(nodeID, sensorID string) (*models.Honeytoken, error)
	InsertHoneytoken(h models.Honeytoken) error
	FindHoneytokens(usernames []string) ([]models.Honeytoken, error)
	RecordHoneytokenUse(id, ts string) error
	ListHoneytokens() ([]models.Honeytoken, error)
}

// Publisher receives honeytoken inventory records (never secrets) so the SIEM
// can watch for the planted usernames on real systems.
type Publisher interface {
	QueueHoneytoken(h models.Honeytoken)
}

type Service struct {
	store     Store
	mu        sync.Mutex
	publisher Publisher
}

// SetPublisher forwards new honeytokens and periodic resyncs to the SIEM.
func (s *Service) SetPublisher(p Publisher) { s.publisher = p }

func NewService(store Store) *Service {
	return &Service{store: store}
}

// NodeCaptureKey returns the capture HMAC key for one node's decoys, derived
// from the master key (created on first use). The master is read from the
// store every time rather than cached, so a purge that wipes it is honoured.
func (s *Service) NodeCaptureKey(nodeID string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	master, err := s.captureKeyLocked()
	if err != nil {
		return "", err
	}
	return deriveNodeKey(master, nodeID), nil
}

func deriveNodeKey(master, nodeID string) string {
	return hmacHex(master, "truesignal-capture-node:"+nodeID)
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
// were produced with the reporting node's key.
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
			ID:        "ht_" + id,
			Username:  user,
			Secret:    secret,
			NodeID:    nodeID,
			SensorID:  sensorID,
			CreatedAt: time.Now().UTC().Format(time.RFC3339),
		}
		if lastErr = s.store.InsertHoneytoken(h); lastErr == nil {
			if s.publisher != nil {
				s.publisher.QueueHoneytoken(h)
			}
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

// candidatePasswords returns the password evidence in an event: HMACs made
// with this node's key (hmac_key_id must match, so captures under any other
// key are ignored) and plaintext captures from plain mode.
func candidatePasswords(details map[string]any, nodeKey string) (hmacs, plain []string) {
	id, _ := details["hmac_key_id"].(string)
	for k, v := range details {
		str, ok := v.(string)
		if !ok || str == "" {
			continue
		}
		switch {
		case strings.HasSuffix(k, "password_hmac") && id == keyID(nodeKey):
			hmacs = append(hmacs, strings.ToLower(str))
		case k == "password" || k == "attempted_password":
			plain = append(plain, str)
		}
	}
	return hmacs, plain
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
	nodeKey, err := s.NodeCaptureKey(e.NodeID)
	if err != nil {
		return nil, err
	}
	users := candidateUsernames(details)
	hmacs, plain := candidatePasswords(details, nodeKey)

	found := map[string]*Match{}
	var order []string
	note := func(t models.Honeytoken, on string) {
		m, ok := found[t.ID]
		if !ok {
			m = &Match{Token: t}
			found[t.ID] = m
			order = append(order, t.ID)
		}
		if !strings.Contains(m.MatchedOn, on) {
			if m.MatchedOn != "" {
				m.MatchedOn += "+"
			}
			m.MatchedOn += on
		}
	}

	byUser, err := s.store.FindHoneytokens(users)
	if err != nil {
		return nil, err
	}
	for _, t := range byUser {
		note(t, "username")
	}

	// Password evidence is compared against every honeytoken under this
	// node's key. Deception deployments hold few tokens, so this is cheap.
	if len(hmacs) > 0 || len(plain) > 0 {
		all, err := s.store.ListHoneytokens()
		if err != nil {
			return nil, err
		}
		for _, t := range all {
			want := hmacHex(nodeKey, t.Secret)
			hit := false
			for _, h := range hmacs {
				hit = hit || hmac.Equal([]byte(h), []byte(want))
			}
			for _, p := range plain {
				hit = hit || hmac.Equal([]byte(p), []byte(t.Secret))
			}
			if hit {
				note(t, "password")
			}
		}
	}

	out := make([]Match, 0, len(order))
	for _, id := range order {
		out = append(out, *found[id])
	}
	return out, nil
}

// RecordUse notes that a honeytoken was used.
func (s *Service) RecordUse(id string) error {
	return s.store.RecordHoneytokenUse(id, time.Now().UTC().Format(time.RFC3339))
}

// StartWatchlistSync publishes every honeytoken to the SIEM at start and then
// every interval, so a SIEM watchlist or indicator index stays complete even
// after its own retention ages out the creation records.
func (s *Service) StartWatchlistSync(ctx context.Context, interval time.Duration) {
	if s.publisher == nil {
		return
	}
	publish := func() {
		tokens, err := s.store.ListHoneytokens()
		if err != nil {
			log.Printf("[WARNING] Honeytoken watchlist sync failed: %v", err)
			return
		}
		for _, t := range tokens {
			s.publisher.QueueHoneytoken(t)
		}
	}
	go func() {
		publish()
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				publish()
			}
		}
	}()
}
