package config

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/truesignal/hub/internal/models"
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

	return &Config{
		DashboardPassword: getEnv("TS_DASHBOARD_PASSWORD", ""),
		DBPath:            getEnv("TS_DB_PATH", "truesignal.db"),
		Port:              getEnv("TS_PORT", "8080"),
		Version:           models.HubVersion,
		Env:               getEnv("TS_ENV", "production"),
		TrustProxy:        isProxyTrusted,

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
	FactoryReset() error
	FactoryResetDryRun() (map[string]int, error)
}

type SessionManager interface {
	ClearAllSessions()
	ClearNodeCache()
}

type SiemService interface {
	UpdateConfig(address, protocol string)
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
	"siemAddress": {}, "siemProtocol": {}, "whitelistedSources": {},
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
	if v, ok := req["siemAddress"]; ok {
		str, isStr := v.(string)
		if !isStr {
			return &ValidationError{"siemAddress must be a string"}
		}
		if str != "" {
			host, port, err := net.SplitHostPort(str)
			p, perr := strconv.Atoi(port)
			if err != nil || host == "" || perr != nil || p < 1 || p > 65535 {
				return &ValidationError{"siemAddress must be host:port"}
			}
		}
	}
	if err := validateEnum(req, "webhookType", "ntfy", "gotify", "discord", "slack", "none"); err != nil {
		return err
	}
	if err := validateEnum(req, "siemProtocol", "tcp", "udp", "tls"); err != nil {
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
	var siemAddress, siemProtocol string
	if val, ok := req["siemAddress"].(string); ok {
		siemAddress = val
	} else {
		siemAddress, _ = s.store.GetConfigValue("siem_address")
	}
	if val, ok := req["siemProtocol"].(string); ok {
		siemProtocol = strings.ToLower(val)
	} else {
		siemProtocol, _ = s.store.GetConfigValue("siem_protocol")
	}
	s.siemService.UpdateConfig(siemAddress, siemProtocol)

	isArmed, _ := s.store.GetConfigValue("is_armed")
	webhookType, _ := s.store.GetConfigValue("webhook_type")
	webhookURL, _ := s.store.GetConfigValue("webhook_url")
	webhookEvents, _ := s.store.GetConfigValue("webhook_events")
	s.notifyService.UpdateConfig(isArmed == "true", webhookType, webhookURL, webhookEvents)

	return nil
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

func (s *Service) FactoryReset(password, ip string) error {
	if err := s.verifyAdminPassword(password); err != nil {
		return err
	}

	log.Printf("[!] AUDIT: IP %s initiated a full Factory Reset. Wiping database.", ip)

	if err := s.store.FactoryReset(); err != nil {
		return errors.New("database_error")
	}

	s.sessionManager.ClearAllSessions()
	s.sessionManager.ClearNodeCache()
	return nil
}

func (s *Service) FactoryResetDryRun(password string) (map[string]int, error) {
	if err := s.verifyAdminPassword(password); err != nil {
		return nil, err
	}

	return s.store.FactoryResetDryRun()
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
