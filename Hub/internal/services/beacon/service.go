// Package beacon creates callback tokens (DNS names, web bugs, kubeconfig
// files) and resolves the ones Token Receivers report.
//
// A token is 24 lowercase base32 characters: 10 random bytes and a 5-byte
// tag, HMAC-SHA256(receiverKey, "truesignal-beacon-v1:" || random). Receivers
// get receiverKey (TS_BEACON_KEY) and check the tag offline, so names a
// scanner invents under the zone never become events. receiverKey is derived
// from the Hub's beacon_master_key, which never leaves the Hub, and is the
// same for every receiver: a beacon keeps working when its receiver is
// redeployed, relinked or doubled for DNS redundancy. The format and test
// vector are shared with Sensors/official/TokenReceiver.
package beacon

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/truesignal/hub/internal/models"
)

// Trigger is the event a Token Receiver raises for a used beacon.
const Trigger = "beacon_triggered"

// ReceiverSensorID is the Token Receiver's manifest ID.
const ReceiverSensorID = "ts-sensor-token-receiver"

const masterKeyConfig = "beacon_master_key"

// Beacon types.
const (
	TypeDNS        = "dns"
	TypeWebBug     = "web_bug"
	TypeKubeconfig = "kubeconfig"
)

var types = map[string]bool{TypeDNS: true, TypeWebBug: true, TypeKubeconfig: true}

const (
	tokenRandom = 10
	tokenTag    = 5
	tokenDomain = "truesignal-beacon-v1:"
)

var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// ErrInvalid is returned for a create request that fails validation.
var ErrInvalid = errors.New("invalid beacon")

type Store interface {
	GetConfigValue(key string) (string, error)
	UpdateConfigValue(key, value string) error
	InsertBeacon(b models.Beacon) error
	GetBeacon(id string) (*models.Beacon, error)
	GetBeaconByToken(token string) (*models.Beacon, error)
	ListBeacons() ([]models.Beacon, error)
	DeleteBeacon(id string) (bool, error)
	RecordBeaconUse(id, ts string) error
	BeaconDomains(receiverSensorID string) ([]string, error)
}

type Service struct {
	store Store
	mu    sync.Mutex
}

func NewService(store Store) *Service { return &Service{store: store} }

// ReceiverKey is TS_BEACON_KEY for Token Receivers, derived from the master
// key (created on first use).
func (s *Service) ReceiverKey() (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	master, err := s.store.GetConfigValue(masterKeyConfig)
	if err == nil && master != "" {
		return deriveReceiverKey(master), nil
	}
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	master = hex.EncodeToString(b)
	if err := s.store.UpdateConfigValue(masterKeyConfig, master); err != nil {
		return "", err
	}
	return deriveReceiverKey(master), nil
}

func deriveReceiverKey(master string) string {
	mac := hmac.New(sha256.New, []byte(master))
	mac.Write([]byte("truesignal-beacon-receiver"))
	return hex.EncodeToString(mac.Sum(nil))
}

func tag(key string, random []byte) []byte {
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write([]byte(tokenDomain))
	mac.Write(random)
	return mac.Sum(nil)[:tokenTag]
}

// makeToken builds a token from random bytes under key.
func makeToken(key string, random []byte) string {
	return strings.ToLower(b32.EncodeToString(append(append([]byte{}, random...), tag(key, random)...)))
}

// CreateRequest is what the operator supplies.
type CreateRequest struct {
	Type   string `json:"type"`
	Name   string `json:"name"`
	Memo   string `json:"memo"`
	Domain string `json:"domain"`
}

var domainRe = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$`)

// Create validates req and stores a new beacon. An empty Domain takes the
// zone of the deployed Token Receiver when exactly one zone is configured.
func (s *Service) Create(req CreateRequest) (models.Beacon, error) {
	req.Type = strings.TrimSpace(req.Type)
	req.Name = strings.TrimSpace(req.Name)
	req.Memo = strings.TrimSpace(req.Memo)
	req.Domain = strings.ToLower(strings.Trim(strings.TrimSpace(req.Domain), "."))
	switch {
	case !types[req.Type]:
		return models.Beacon{}, fmt.Errorf("%w: type must be dns, web_bug or kubeconfig", ErrInvalid)
	case req.Name == "" || len(req.Name) > 128:
		return models.Beacon{}, fmt.Errorf("%w: name is required (up to 128 characters): say where it is planted", ErrInvalid)
	case len(req.Memo) > 512:
		return models.Beacon{}, fmt.Errorf("%w: memo is limited to 512 characters", ErrInvalid)
	}
	if req.Domain == "" {
		domains, err := s.Domains()
		if err != nil {
			return models.Beacon{}, err
		}
		if len(domains) != 1 {
			return models.Beacon{}, fmt.Errorf("%w: choose the zone (deployed Token Receivers serve %d)", ErrInvalid, len(domains))
		}
		req.Domain = domains[0]
	}
	if len(req.Domain) > 200 || !domainRe.MatchString(req.Domain) {
		return models.Beacon{}, fmt.Errorf("%w: domain %q is not a host name", ErrInvalid, req.Domain)
	}

	key, err := s.ReceiverKey()
	if err != nil {
		return models.Beacon{}, err
	}
	var lastErr error
	for attempt := 0; attempt < 5; attempt++ {
		random := make([]byte, tokenRandom)
		idb := make([]byte, 4)
		if _, err := rand.Read(random); err != nil {
			return models.Beacon{}, err
		}
		if _, err := rand.Read(idb); err != nil {
			return models.Beacon{}, err
		}
		b := models.Beacon{
			ID:        "bc_" + hex.EncodeToString(idb),
			Token:     makeToken(key, random),
			Type:      req.Type,
			Name:      req.Name,
			Memo:      req.Memo,
			Domain:    req.Domain,
			CreatedAt: time.Now().UTC().Format(time.RFC3339),
		}
		if lastErr = s.store.InsertBeacon(b); lastErr == nil {
			return b, nil
		}
	}
	return models.Beacon{}, fmt.Errorf("creating beacon: %w", lastErr)
}

func (s *Service) List() ([]models.Beacon, error)        { return s.store.ListBeacons() }
func (s *Service) Get(id string) (*models.Beacon, error) { return s.store.GetBeacon(id) }
func (s *Service) Delete(id string) (bool, error)        { return s.store.DeleteBeacon(id) }
func (s *Service) Domains() ([]string, error)            { return s.store.BeaconDomains(ReceiverSensorID) }
func (s *Service) RecordUse(id string) error {
	return s.store.RecordBeaconUse(id, time.Now().UTC().Format(time.RFC3339))
}

// Resolve returns the beacon a reported token belongs to, or nil for a
// token the Hub does not know (deleted beacon, or forged by the node).
func (s *Service) Resolve(token string) (*models.Beacon, error) {
	token = strings.ToLower(strings.TrimSpace(token))
	if len(token) != 24 {
		return nil, nil
	}
	return s.store.GetBeaconByToken(token)
}

// Artifact is what the operator plants.
type Artifact struct {
	Filename    string `json:"filename"`
	ContentType string `json:"contentType"`
	Content     string `json:"content"`
	// Value is the bare host name or URL, for copying.
	Value string `json:"value"`
}

var slugRe = regexp.MustCompile(`[^a-z0-9]+`)

func slug(s, fallback string) string {
	s = strings.Trim(slugRe.ReplaceAllString(strings.ToLower(s), "-"), "-")
	if len(s) > 40 {
		s = strings.Trim(s[:40], "-")
	}
	if s == "" {
		return fallback
	}
	return s
}

// derived is a stable pseudo-random string for the artifact's decoration
// (fake credentials), so downloading it twice gives the same file.
func derived(token, purpose string, n int) string {
	sum := sha256.Sum256([]byte(purpose + ":" + token))
	return base64.RawURLEncoding.EncodeToString(sum[:])[:n]
}

// Render produces the artifact for b. It is deterministic.
func Render(b models.Beacon) Artifact {
	host := b.Token + "." + b.Domain
	switch b.Type {
	case TypeWebBug:
		url := "http://" + b.Domain + "/static/" + b.Token + ".gif"
		return Artifact{
			Filename:    slug(b.Name, "web-bug") + "-web-bug.html",
			ContentType: "text/html",
			Value:       url,
			Content: "<!-- TrueSignal web bug \"" + strings.ReplaceAll(b.Name, "--", "-") + "\": embed in an HTML page, e-mail or document that loads remote images. -->\n" +
				"<img src=\"" + url + "\" width=\"1\" height=\"1\" alt=\"\" style=\"display:none\">\n",
		}
	case TypeKubeconfig:
		// No certificate-authority-data: kubectl would reject fake CA data
		// before it resolves the server, and the lookup is the beacon.
		cluster := slug(b.Name, "prod")
		return Artifact{
			Filename:    "kubeconfig-" + cluster + ".yaml",
			ContentType: "application/yaml",
			Value:       host,
			Content: "apiVersion: v1\nkind: Config\nclusters:\n- cluster:\n    insecure-skip-tls-verify: true\n" +
				"    server: https://" + host + ":6443\n  name: " + cluster + "\ncontexts:\n- context:\n    cluster: " + cluster + "\n    user: " + cluster + "-admin\n" +
				"  name: " + cluster + "\ncurrent-context: " + cluster + "\npreferences: {}\nusers:\n- name: " + cluster + "-admin\n  user:\n" +
				"    token: " + derived(b.Token, "user", 43) + "\n",
		}
	default:
		return Artifact{
			Filename:    slug(b.Name, "dns") + "-dns-token.txt",
			ContentType: "text/plain",
			Value:       host,
			Content: "# TrueSignal DNS beacon \"" + b.Name + "\". Any lookup of this name raises an alert.\n" + host + "\n\n" +
				"# Placement ideas (only an intruder should ever resolve it):\n" +
				"#   ~/.ssh/config:     Host backup-db  HostName " + host + "\n" +
				"#   /etc/hosts-style inventory, .env:  DB_HOST=" + host + "\n" +
				"#   a script or .bashrc alias that an attacker would run\n",
		}
	}
}
