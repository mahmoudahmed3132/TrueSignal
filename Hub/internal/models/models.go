package models

import (
	"encoding/json"
	"errors"
	"strings"

	"github.com/truesignal/hub/internal/assets"
	"github.com/truesignal/hub/internal/attack"
)

// HubVersion defines the backend protocol version for resolving compatible sensors and authenticating Agents.
const HubVersion = "2.3.0"

// ErrNotFound is returned by stores when the addressed row does not exist.
var ErrNotFound = errors.New("not found")

// ValidSeverities is the closed set of event severities, lowest first.
var ValidSeverities = []string{"info", "low", "medium", "high", "critical"}

// NormalizeSeverity lower-cases and validates a severity. Unknown values map to
// "medium" (the schema default) rather than rejecting the event: a decoy alert
// must never be dropped because of a misconfigured severity.
func NormalizeSeverity(sev string) (string, bool) {
	clean := strings.ToLower(strings.TrimSpace(sev))
	for _, v := range ValidSeverities {
		if clean == v {
			return clean, true
		}
	}
	return "medium", false
}

// SetupPayload represents the initial setup POST request
type SetupPayload struct {
	Password    string `json:"password"`
	HubEndpoint string `json:"hubEndpoint"`
	// SetupToken is the one-time token printed in the Hub log on first start.
	SetupToken string `json:"setupToken"`
}

// ConfigPayload represents the runtime configuration of the Hub
type ConfigPayload struct {
	HubEndpoint              string   `json:"hubEndpoint"`
	RegistryURL              string   `json:"registryUrl"`
	AutoArchiveDays          int      `json:"autoArchiveDays"`
	AutoPurgeDays            int      `json:"autoPurgeDays"`
	AutoPurgeHeartbeatsDays  int      `json:"autoPurgeHeartbeatsDays"`
	UpdateCheckIntervalHours int      `json:"updateCheckIntervalHours"`
	WebhookURL               string   `json:"webhookUrl"`
	WebhookType              string   `json:"webhookType"`
	WebhookEvents            []string `json:"webhookEvents"`
	SiemAddress              string   `json:"siemAddress"`
	SiemProtocol             string   `json:"siemProtocol"`
	SiemFormat               string   `json:"siemFormat"`
	// SiemTokenSet reports whether an HTTP output token is stored; the token
	// itself is write-only and never returned.
	SiemTokenSet       bool   `json:"siemTokenSet"`
	WhitelistedSources string `json:"whitelistedSources"`
	KnownScanners      string `json:"knownScanners"`
}

type Event struct {
	ID           int             `json:"id,omitempty"`
	NodeID       string          `json:"nodeId,omitempty"`
	SensorID     string          `json:"sensorId"`
	Timestamp    string          `json:"timestamp"`
	EventTrigger string          `json:"eventTrigger"`
	Severity     string          `json:"severity"`
	Source       string          `json:"source"`
	Target       string          `json:"target"`
	Details      json.RawMessage `json:"details"`
	IsRead       bool            `json:"isRead"`
	IsArchived   bool            `json:"isArchived"`
	Count        int             `json:"count"`
	// Whitelisted marks events from whitelisted sources (stored archived, not
	// notified). Not persisted as a column.
	Whitelisted bool `json:"whitelisted,omitempty"`
	// KnownScanner marks events from the known-scanner list (authorized
	// scanners, bots): handled like whitelisted, flagged separately for the
	// SIEM. Not persisted as a column.
	KnownScanner bool `json:"knownScanner,omitempty"`
	// Attack is the trigger's MITRE ATT&CK mapping (package attack),
	// derived on read; nil for unmapped triggers. Not persisted.
	Attack *attack.Mapping `json:"attack,omitempty"`
	// SourceAsset is the inventory asset the source address belongs to
	// (package assets), resolved against the current inventory; nil when
	// none. Not persisted.
	SourceAsset *assets.Ref `json:"sourceAsset,omitempty"`
}

// Heartbeat represents a routine ping from a sensor
type Heartbeat struct {
	SensorID  string `json:"sensorId"`
	ConfigRev string `json:"configRev"`
}

// Node represents a physical server managing sensors
type Node struct {
	ID                 string       `json:"nodeId"`
	Alias              string       `json:"alias"`
	APIKey             string       `json:"-"` // never serialized; keys are stored hashed
	ActiveRevision     string       `json:"activeRevision,omitempty"`
	DesiredRevision    string       `json:"desiredRevision,omitempty"`
	PublicIP           *string      `json:"publicIp"`
	PrivateIP          *string      `json:"privateIp"`
	Tags               []string     `json:"tags"`
	HasPendingConfig   bool         `json:"hasPendingConfig"`
	HasUpdateAvailable bool         `json:"hasUpdateAvailable"`
	LastHeartbeat      *string      `json:"lastHeartbeat"`
	Status             string       `json:"status"`
	InstalledSensors   []NodeSensor `json:"installedSensors"`
}

// NodeSensor represents a deployed sensor on a node
type NodeSensor struct {
	ID              string                 `json:"sensorId"`
	NodeID          string                 `json:"nodeId"`
	Name            string                 `json:"name"`
	Display         string                 `json:"display"`
	Status          string                 `json:"status"`
	LastHeartbeat   *string                `json:"lastHeartbeat"`
	IsSilenced      bool                   `json:"isSilenced"`
	Events24h       int                    `json:"events24h"`
	EnvVars         map[string]interface{} `json:"envVars"`
	DeployedVersion string                 `json:"deployedVersion"`
	UpdateAvailable bool                   `json:"updateAvailable"`
}

// *** manifests ***

type SensorManifest struct {
	ID            string        `json:"id"`
	Version       string        `json:"version"`
	Name          string        `json:"name"`
	Category      string        `json:"category"`
	OSILayer      string        `json:"osi_layer"`
	IconSVG       string        `json:"icon_svg"`
	Description   string        `json:"description"`
	Documentation Documentation `json:"documentation"`
	Heuristics    Heuristics    `json:"heuristics"`
	Deployment    Deployment    `json:"deployment"`
}

type Documentation struct {
	Summary  string       `json:"summary"`
	Sections []DocSection `json:"sections"`
}

type DocSection struct {
	Title   string   `json:"title"`
	Type    string   `json:"type"`
	Content []string `json:"content"`
}

type Heuristics struct {
	Triggers             Triggers `json:"triggers"`
	RecommendationReason string   `json:"recommendation_reason"`
}

type Triggers struct {
	Processes    []string `json:"processes,omitempty"`
	Ports        []int    `json:"ports,omitempty"`
	FilePatterns []string `json:"file_patterns,omitempty"`
	MinMemoryMB  int      `json:"min_memory_mb,omitempty"`
}

type Deployment struct {
	ImageRepository string           `json:"image_repository"`
	ImageTag        string           `json:"image_tag"`
	ImageDigest     string           `json:"image_digest,omitempty"`
	NetworkMode     string           `json:"network_mode,omitempty"`
	User            string           `json:"user,omitempty"`
	CapAdd          []string         `json:"cap_add,omitempty"`
	CapDrop         []string         `json:"cap_drop,omitempty"`
	SecurityOpt     []string         `json:"security_opt,omitempty"`
	PortAssignments []PortAssignment `json:"port_assignments,omitempty"`
	// ListenPortsEnv names the env vars whose values hold the TCP/UDP ports this
	// sensor binds (comma-separated; each item may be "proto:port" or "port").
	// The Hub uses it to reject two sensors on one node binding the same port.
	ListenPortsEnv []string        `json:"listen_ports_env,omitempty"`
	VolumeMounts   []VolumeMount   `json:"volume_mounts,omitempty"`
	InitContainers []InitContainer `json:"init_containers,omitempty"`
	EnvVars        []ConfigVar     `json:"env_vars,omitempty"`
}

type InitContainer struct {
	Name            string        `json:"name"`
	ImageRepository string        `json:"image_repository"`
	ImageTag        string        `json:"image_tag"`
	ImageDigest     string        `json:"image_digest,omitempty"`
	Command         string        `json:"command,omitempty"`
	VolumeMounts    []VolumeMount `json:"volume_mounts,omitempty"`
	User            string        `json:"user,omitempty"`
	CapDrop         []string      `json:"cap_drop,omitempty"`
	CapAdd          []string      `json:"cap_add,omitempty"`
	SecurityOpt     []string      `json:"security_opt,omitempty"`
}

type VolumeType string

const (
	DynamicDirBind  VolumeType = "dynamic_dir_bind"
	DynamicFileBind VolumeType = "dynamic_file_bind"
	Bind            VolumeType = "bind"
)

type VolumeMount struct {
	Type         VolumeType `json:"type"`
	Source       string     `json:"source"`
	Target       string     `json:"target"`
	ReadOnly     bool       `json:"read_only"`
	SourceEnv    string     `json:"source_env,omitempty"`
	TargetPrefix string     `json:"target_prefix,omitempty"`
}

type PortAssignment struct {
	EnvVarName string `json:"env_var_name"`
	Default    int    `json:"default"`
}

type ConfigVar struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Default     string `json:"default"`
	Type        string `json:"type"`
	Required    bool   `json:"required"`
	Hidden      bool   `json:"hidden,omitempty"`
}

// Honeytoken is a fabricated credential the Hub plants in a File Canary lure.
// Any later use of it (a decoy login with its username or password) raises a
// critical honeytoken_used event. Secret is never serialised.
type Honeytoken struct {
	ID         string `json:"id"`
	Username   string `json:"username"`
	Secret     string `json:"-"`
	NodeID     string `json:"nodeId"`
	SensorID   string `json:"sensorId"`
	CreatedAt  string `json:"createdAt"`
	LastUsedAt string `json:"lastUsedAt"`
	UseCount   int    `json:"useCount"`
}
