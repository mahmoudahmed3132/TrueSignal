package config

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/truesignal/hub/internal/models"
	"github.com/truesignal/hub/internal/services/siem"
	"golang.org/x/crypto/bcrypt"
)

// Config represents immutable infrastructure-level settings.
// Runtime settings (like API keys, webhooks, and SIEM) are managed in SQLite.
type Config struct {
	DashboardPassword string // Optional override. If set, bypasses the Setup UI.
	DBPath            string
	Port              string
	Version           string
	Env               string
	TrustProxy        bool
	// TrustedProxies (TS_TRUSTED_PROXIES: comma-separated IPs or CIDRs)
	// limits TrustProxy to requests whose TCP peer is one of these proxies.
	// Empty means any peer, which lets a client that reaches the Hub
	// directly spoof its IP; main warns at startup.
	TrustedProxies []netip.Prefix
	// RequireMFA (TS_REQUIRE_MFA=true) forces admin MFA: until it is
	// enrolled, a login can only reach the enrollment endpoints, and it
	// cannot be disabled from the dashboard.
	RequireMFA bool

	// SessionTTL / SessionIdle bound dashboard sessions (TS_SESSION_TTL,
	// TS_SESSION_IDLE_TIMEOUT; Go durations, idle "0" disables).
	SessionTTL  time.Duration
	SessionIdle time.Duration
	// AllowUnpinnedImages permits deploying manifests without an image digest
	// (TS_ALLOW_UNPINNED_IMAGES=true). Intended for local development only.
	AllowUnpinnedImages bool
	// SIEMCAFile optionally pins the CA bundle used for syslog over TLS.
	SIEMCAFile string
	// SyslogPEN is the IANA Private Enterprise Number used in RFC 5424
	// SD-IDs (truesignal@<PEN>). Defaults to 32473, the RFC 5612
	// documentation PEN; set your organisation's registered PEN.
	SyslogPEN string
}

// TrustsProxyHeaders reports whether r's forwarding headers (X-Real-IP,
// X-Forwarded-For, X-Forwarded-Host) may be believed: TS_TRUST_PROXY is on
// and, when TS_TRUSTED_PROXIES is set, the TCP peer is one of those proxies.
func (c *Config) TrustsProxyHeaders(r *http.Request) bool {
	if c == nil || !c.TrustProxy {
		return false
	}
	if len(c.TrustedProxies) == 0 {
		return true
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	addr = addr.Unmap()
	for _, p := range c.TrustedProxies {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// ParseTrustedProxies parses a comma-separated list of IPs and CIDRs.
func ParseTrustedProxies(raw string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if strings.Contains(part, "/") {
			p, err := netip.ParsePrefix(part)
			if err != nil {
				return nil, fmt.Errorf("invalid TS_TRUSTED_PROXIES entry %q: %w", part, err)
			}
			out = append(out, p.Masked())
			continue
		}
		a, err := netip.ParseAddr(part)
		if err != nil {
			return nil, fmt.Errorf("invalid TS_TRUSTED_PROXIES entry %q: %w", part, err)
		}
		a = a.Unmap()
		out = append(out, netip.PrefixFrom(a, a.BitLen()))
	}
	return out, nil
}

// IsDevelopment reports whether the Hub runs outside production mode.
func (c *Config) IsDevelopment() bool { return c.Env != "production" }

func getDuration(key string, fallback time.Duration) time.Duration {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback
	}
	if raw == "0" {
		return 0
	}
	d, err := time.ParseDuration(raw)
	if err != nil || d < 0 {
		log.Printf("[WARNING] Invalid %s=%q, using default %s", key, raw, fallback)
		return fallback
	}
	return d
}

func getBool(key string) bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv(key)))
	return v == "true" || v == "1"
}

func getEnv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
}

func Load() *Config {
	trustProxyStr := strings.ToLower(getEnv("TS_TRUST_PROXY", "false"))
	isProxyTrusted := trustProxyStr == "true" || trustProxyStr == "1"
	// A typo here must not silently widen trust to every peer.
	trustedProxies, err := ParseTrustedProxies(getEnv("TS_TRUSTED_PROXIES", ""))
	if err != nil {
		log.Fatalf("[FATAL] %v", err)
	}

	return &Config{
		DashboardPassword: getEnv("TS_DASHBOARD_PASSWORD", ""),
		DBPath:            getEnv("TS_DB_PATH", "truesignal.db"),
		Port:              getEnv("TS_PORT", "8080"),
		Version:           models.HubVersion,
		Env:               getEnv("TS_ENV", "production"),
		TrustProxy:        isProxyTrusted,
		TrustedProxies:    trustedProxies,
		RequireMFA:        getBool("TS_REQUIRE_MFA"),

		SessionTTL:          getDuration("TS_SESSION_TTL", 12*time.Hour),
		SessionIdle:         getDuration("TS_SESSION_IDLE_TIMEOUT", 15*time.Minute),
		AllowUnpinnedImages: getBool("TS_ALLOW_UNPINNED_IMAGES"),
		SIEMCAFile:          getEnv("TS_SIEM_CA_FILE", ""),
		SyslogPEN:           getEnv("TS_SYSLOG_PEN", "32473"),
	}
}

type Store interface {
	GetConfigValue(key string) (string, error)
	CompleteSetup(adminHash, hubEndpoint string) error
	GetAllConfig() (map[string]string, error)
	UpdateConfigBatch(updates map[string]interface{}) error
	UpdateConfigValue(key, value string) error
	FactoryReset(purgeHoneytokens bool) error
	FactoryResetDryRun(purgeHoneytokens bool) (map[string]int, error)
}

type SessionManager interface {
	ClearAllSessions()
	ClearNodeCache()
}

type SiemService interface {
	UpdateConfig(out siem.Output)
}

type NotifyService interface {
	UpdateConfig(isArmed bool, webhookType, webhookURL, webhookEvents string)
	UpdateIsArmed(isArmed bool)
}

type Service struct {
	store             Store
	sessionManager    SessionManager
	siemService       SiemService
	notifyService     NotifyService
	dashboardPassword string
	version           string

	setupMu    sync.Mutex
	setupToken string
}

func NewService(store Store, sm SessionManager, siemService SiemService, notifyService NotifyService, dashboardPassword, version string) *Service {
	return &Service{
		store:             store,
		sessionManager:    sm,
		siemService:       siemService,
		notifyService:     notifyService,
		dashboardPassword: dashboardPassword,
		version:           version,
	}
}

func (s *Service) GetSetupStatus() (bool, error) {
	if s.dashboardPassword != "" {
		return false, nil
	}
	isSetup, err := s.store.GetConfigValue("is_setup")
	return err != nil || isSetup != "true", nil
}

// EnsureSetupToken returns the one-time token required to complete first-run
// setup, generating it if needed. Without it, whoever reaches a fresh Hub first
// would choose the admin password. TS_SETUP_TOKEN overrides the generated value
// (for automated installs). Returns "" when setup is not required.
func (s *Service) EnsureSetupToken() string {
	if required, _ := s.GetSetupStatus(); !required {
		return ""
	}
	s.setupMu.Lock()
	defer s.setupMu.Unlock()
	if s.setupToken != "" {
		return s.setupToken
	}
	if env := strings.TrimSpace(os.Getenv("TS_SETUP_TOKEN")); env != "" {
		s.setupToken = env
		return s.setupToken
	}
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		log.Printf("[FATAL] cannot generate setup token: %v", err)
		return ""
	}
	s.setupToken = hex.EncodeToString(buf)
	return s.setupToken
}

func (s *Service) CompleteSetup(password, hubEndpoint, setupToken string) error {
	if s.dashboardPassword != "" {
		return errors.New("setup_locked")
	}

	isSetup, err := s.store.GetConfigValue("is_setup")
	if err == nil && isSetup == "true" {
		return errors.New("already_setup")
	}

	expected := s.EnsureSetupToken()
	if expected == "" || subtle.ConstantTimeCompare([]byte(strings.TrimSpace(setupToken)), []byte(expected)) != 1 {
		return errors.New("invalid_setup_token")
	}
	if len(password) < 12 {
		return errors.New("weak_password")
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	if err := s.store.CompleteSetup(string(hash), hubEndpoint); err != nil {
		return err
	}
	s.setupMu.Lock()
	s.setupToken = ""
	s.setupMu.Unlock()
	return nil
}

// verifyAdminPassword checks the admin password against the env override when
// set (TS_DASHBOARD_PASSWORD), otherwise against the stored bcrypt hash.
func (s *Service) verifyAdminPassword(password string) error {
	if s.dashboardPassword != "" {
		if subtle.ConstantTimeCompare([]byte(password), []byte(s.dashboardPassword)) == 1 {
			return nil
		}
		return errors.New("incorrect_password")
	}
	dbHash, err := s.store.GetConfigValue("admin_hash")
	if err != nil {
		return errors.New("database_error")
	}
	if err := bcrypt.CompareHashAndPassword([]byte(dbHash), []byte(password)); err != nil {
		return errors.New("incorrect_password")
	}
	return nil
}

func (s *Service) GetConfig() (models.ConfigPayload, error) {
	kv, err := s.store.GetAllConfig()
	if err != nil {
		return models.ConfigPayload{}, err
	}

	archiveDays, _ := strconv.Atoi(kv["auto_archive_days"])
	purgeDays, _ := strconv.Atoi(kv["auto_purge_days"])
	purgeHeartbeatsDays, _ := strconv.Atoi(kv["auto_purge_heartbeats_days"])
	updateCheckIntervalHours, _ := strconv.Atoi(kv["update_check_interval_hours"])
	if kv["update_check_interval_hours"] == "" {
		updateCheckIntervalHours = 24 // Default
	}

	var events []string
	if kv["webhook_events"] != "" {
		events = strings.Split(kv["webhook_events"], ",")
	}

	return models.ConfigPayload{
		HubEndpoint:              kv["hub_endpoint"],
		RegistryURL:              kv["registry_url"],
		AutoArchiveDays:          archiveDays,
		AutoPurgeDays:            purgeDays,
		AutoPurgeHeartbeatsDays:  purgeHeartbeatsDays,
		UpdateCheckIntervalHours: updateCheckIntervalHours,
		WebhookURL:               kv["webhook_url"],
		WebhookType:              kv["webhook_type"],
		WebhookEvents:            events,
		SiemAddress:              kv["siem_address"],
		SiemProtocol:             kv["siem_protocol"],
		SiemFormat:               kv["siem_format"],
		SiemTokenSet:             kv["siem_token"] != "",
		WhitelistedSources:       kv["whitelisted_sources"],
	}, nil
}

// ValidationError marks a client-side configuration mistake (HTTP 400).
type ValidationError struct{ Msg string }

func (e *ValidationError) Error() string { return e.Msg }

func validateHTTPURL(field string, v interface{}) error {
	str, ok := v.(string)
	if !ok {
		return &ValidationError{field + " must be a string"}
	}
	if str == "" {
		return nil
	}
	u, err := url.Parse(str)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return &ValidationError{field + " must be an http(s) URL"}
	}
	return nil
}

// knownConfigKeys is the set of camelCase fields UpdateConfig knows how to
// persist. Anything else is rejected so a typo'd or snake_case key can't return
// success while silently applying nothing.
var knownConfigKeys = map[string]struct{}{
	"hubEndpoint": {}, "registryUrl": {}, "autoArchiveDays": {},
	"autoPurgeDays": {}, "autoPurgeHeartbeatsDays": {}, "updateCheckIntervalHours": {},
	"webhookType": {}, "webhookUrl": {}, "webhookEvents": {},
	"siemAddress": {}, "siemProtocol": {}, "siemFormat": {}, "siemToken": {},
	"whitelistedSources": {},
}

func validateConfigUpdate(req map[string]interface{}) error {
	for k := range req {
		if _, ok := knownConfigKeys[k]; !ok {
			return &ValidationError{fmt.Sprintf("unknown config field: %s", k)}
		}
	}
	for _, f := range []string{"hubEndpoint", "webhookUrl", "registryUrl"} {
		if v, ok := req[f]; ok {
			if err := validateHTTPURL(f, v); err != nil {
				return err
			}
		}
	}
	for _, f := range []string{"siemAddress", "siemToken"} {
		if v, ok := req[f]; ok {
			if _, isStr := v.(string); !isStr {
				return &ValidationError{f + " must be a string"}
			}
		}
	}
	if v, ok := req["siemToken"].(string); ok && strings.ContainsAny(v, "\r\n") {
		return &ValidationError{"siemToken must be a single line"}
	}
	if err := validateEnum(req, "webhookType", "ntfy", "gotify", "discord", "slack", "none"); err != nil {
		return err
	}
	if err := validateEnum(req, "siemProtocol", "tcp", "udp", "tls", siem.ProtocolElastic, siem.ProtocolLogScale); err != nil {
		return err
	}
	if err := validateEnum(req, "siemFormat", siem.FormatRFC5424, siem.FormatECS); err != nil {
		return err
	}
	if v, ok := req["webhookEvents"]; ok {
		list, isList := v.([]interface{})
		if !isList {
			return &ValidationError{"webhookEvents must be a list of severities"}
		}
		for _, item := range list {
			sev, isStr := item.(string)
			if _, valid := models.NormalizeSeverity(sev); !isStr || !valid {
				return &ValidationError{fmt.Sprintf("webhookEvents contains an unknown severity: %v", item)}
			}
		}
	}
	for _, f := range []string{"autoArchiveDays", "autoPurgeDays", "autoPurgeHeartbeatsDays", "updateCheckIntervalHours"} {
		if v, ok := req[f]; ok {
			n, isNum := v.(float64)
			if !isNum || n < 0 || n != float64(int(n)) {
				return &ValidationError{f + " must be a non-negative integer"}
			}
		}
	}
	return nil
}

// effectiveSiemOutput merges the SIEM fields of an update with the stored
// values, so the address can be checked against the protocol it will be used
// with.
func (s *Service) effectiveSiemOutput(req map[string]interface{}) siem.Output {
	pick := func(field, key string) string {
		if v, ok := req[field].(string); ok {
			return v
		}
		v, _ := s.store.GetConfigValue(key)
		return v
	}
	return siem.Output{
		Address:  strings.TrimSpace(pick("siemAddress", "siem_address")),
		Protocol: strings.ToLower(pick("siemProtocol", "siem_protocol")),
		Format:   strings.ToLower(pick("siemFormat", "siem_format")),
		Token:    strings.TrimSpace(pick("siemToken", "siem_token")),
	}
}

// validateSiemAddress checks siemAddress for its protocol: host:port for the
// syslog streams, an https URL for the HTTP outputs (they carry a token).
func validateSiemAddress(protocol, address string) error {
	if address == "" {
		return nil
	}
	if siem.IsHTTPProtocol(protocol) {
		u, err := url.Parse(address)
		if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
			return &ValidationError{"siemAddress must be an https URL for the " + protocol + " output"}
		}
		if protocol == siem.ProtocolElastic && strings.Trim(u.Path, "/") == "" {
			return &ValidationError{"siemAddress for elastic must include the data stream, e.g. https://es.example:9200/logs-truesignal-default"}
		}
		return nil
	}
	host, port, err := net.SplitHostPort(address)
	p, perr := strconv.Atoi(port)
	if err != nil || host == "" || perr != nil || p < 1 || p > 65535 {
		return &ValidationError{"siemAddress must be host:port"}
	}
	return nil
}

// validateEnum rejects a present field whose value is not one of allowed
// (case-insensitive). The store would otherwise drop it silently.
func validateEnum(req map[string]interface{}, field string, allowed ...string) error {
	v, ok := req[field]
	if !ok {
		return nil
	}
	str, isStr := v.(string)
	if isStr {
		for _, a := range allowed {
			if strings.EqualFold(str, a) {
				return nil
			}
		}
	}
	return &ValidationError{fmt.Sprintf("%s must be one of: %s", field, strings.Join(allowed, ", "))}
}

func (s *Service) UpdateConfig(req map[string]interface{}) error {
	if err := validateConfigUpdate(req); err != nil {
		return err
	}
	out := s.effectiveSiemOutput(req)
	if err := validateSiemAddress(out.Protocol, out.Address); err != nil {
		return err
	}
	// Safely map incoming camelCase API fields to snake_case DB columns
	dbUpdates := make(map[string]interface{})
	mapping := map[string]string{
		"hubEndpoint":              "hub_endpoint",
		"registryUrl":              "registry_url",
		"autoArchiveDays":          "auto_archive_days",
		"autoPurgeDays":            "auto_purge_days",
		"autoPurgeHeartbeatsDays":  "auto_purge_heartbeats_days",
		"updateCheckIntervalHours": "update_check_interval_hours",
		"webhookType":              "webhook_type",
		"webhookUrl":               "webhook_url",
		"webhookEvents":            "webhook_events",
		"siemAddress":              "siem_address",
		"siemProtocol":             "siem_protocol",
		"siemFormat":               "siem_format",
		"siemToken":                "siem_token",
		"whitelistedSources":       "whitelisted_sources",
	}
	for camelKey, snakeKey := range mapping {
		if val, exists := req[camelKey]; exists {
			dbUpdates[snakeKey] = val
		}
	}

	if err := s.store.UpdateConfigBatch(dbUpdates); err != nil {
		return err
	}

	// Hot reload if related settings were changed
	s.siemService.UpdateConfig(out)
	s.reloadNotify()

	return nil
}

func (s *Service) reloadNotify() {
	isArmed, _ := s.store.GetConfigValue("is_armed")
	webhookType, _ := s.store.GetConfigValue("webhook_type")
	webhookURL, _ := s.store.GetConfigValue("webhook_url")
	webhookEvents, _ := s.store.GetConfigValue("webhook_events")
	s.notifyService.UpdateConfig(isArmed == "true", webhookType, webhookURL, webhookEvents)
}

func (s *Service) ChangePassword(currentPassword, newPassword string) error {
	if s.dashboardPassword != "" {
		return errors.New("password_locked")
	}

	dbHash, err := s.store.GetConfigValue("admin_hash")
	if err != nil {
		return errors.New("database_error")
	}

	if err := bcrypt.CompareHashAndPassword([]byte(dbHash), []byte(currentPassword)); err != nil {
		return errors.New("incorrect_password")
	}

	if len(newPassword) < 12 {
		return errors.New("weak_password")
	}

	newHash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return errors.New("hash_error")
	}

	if err := s.store.UpdateConfigValue("admin_hash", string(newHash)); err != nil {
		return errors.New("database_error")
	}

	s.sessionManager.ClearAllSessions()
	return nil
}

// FactoryReset wipes the Hub. Honeytokens and the capture master key are kept
// unless purgeHoneytokens is set (see store.FactoryReset).
func (s *Service) FactoryReset(password, ip string, purgeHoneytokens bool) error {
	if err := s.verifyAdminPassword(password); err != nil {
		return err
	}

	log.Printf("[!] AUDIT: IP %s initiated a full Factory Reset. Wiping database.", ip)

	if err := s.store.FactoryReset(purgeHoneytokens); err != nil {
		return errors.New("database_error")
	}

	s.sessionManager.ClearAllSessions()
	s.sessionManager.ClearNodeCache()
	// Drop the in-memory SIEM output (address, token) and webhook settings so
	// the wiped Hub stops forwarding with the old destinations and secrets.
	s.siemService.UpdateConfig(s.effectiveSiemOutput(nil))
	s.reloadNotify()
	return nil
}

func (s *Service) FactoryResetDryRun(password string, purgeHoneytokens bool) (map[string]int, error) {
	if err := s.verifyAdminPassword(password); err != nil {
		return nil, err
	}

	return s.store.FactoryResetDryRun(purgeHoneytokens)
}

func (s *Service) GetSystemState() (bool, error) {
	isArmedStr, err := s.store.GetConfigValue("is_armed")
	if err != nil {
		return true, nil // Default fallback
	}
	return isArmedStr == "true", nil
}

func (s *Service) SetSystemState(isArmed bool) error {
	val := "false"
	if isArmed {
		val = "true"
	}

	if err := s.store.UpdateConfigValue("is_armed", val); err != nil {
		return err
	}

	s.notifyService.UpdateIsArmed(isArmed)
	return nil
}

func (s *Service) GetVersion() string {
	return s.version
}

func (s *Service) GetAcknowledgedWizardRelease() (string, error) {
	val, err := s.store.GetConfigValue("acknowledged_wizard_release")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(val), nil
}

func (s *Service) AcknowledgeWizardRelease(version string) error {
	return s.store.UpdateConfigValue("acknowledged_wizard_release", strings.TrimSpace(version))
}
