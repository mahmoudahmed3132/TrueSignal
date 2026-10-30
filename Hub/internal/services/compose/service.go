package composesvc

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/mod/semver"

	"github.com/truesignal/hub/internal/catalog"
	composeEngine "github.com/truesignal/hub/internal/compose"
	"github.com/truesignal/hub/internal/compose/security"
	"github.com/truesignal/hub/internal/models"
	"github.com/truesignal/hub/internal/services/node"
	"github.com/truesignal/hub/internal/signing"
	"gopkg.in/yaml.v3"
)

type Store interface {
	GetNodeByKey(token string) (string, error)
	GetNodeDetails(nodeID string) (*models.Node, error)
	GetConfigValue(key string) (string, error)
	SetNodeDesiredRevision(nodeID, rev string) error
	SetNodeSensorDeployedVersion(nodeID, sensorID, version string) error
	ApplyNodeRevision(nodeID, revision string) error
}

type Service struct {
	store         Store
	catalog       *catalog.Service
	cache         map[string]models.SensorManifest
	mu            sync.RWMutex
	allowUnpinned bool
	honeytokens   HoneytokenProvider
	beacons       BeaconKeyProvider
	verifier      signing.ManifestVerifier
}

// SetManifestVerifier makes the Hub accept only registry manifests whose
// Sigstore bundle verifies (main wires it unless TS_ALLOW_UNSIGNED_MANIFESTS).
func (s *Service) SetManifestVerifier(v signing.ManifestVerifier) { s.verifier = v }

// HoneytokenProvider supplies each node's capture key and each File Canary
// instance's planted credential.
type HoneytokenProvider interface {
	NodeCaptureKey(nodeID string) (string, error)
	TokenFor(nodeID, sensorID string) (models.Honeytoken, error)
}

// SetHoneytokens enables injection of TS_CAPTURE_HASH_KEY and TS_HONEYTOKEN.
func (s *Service) SetHoneytokens(p HoneytokenProvider) { s.honeytokens = p }

// BeaconKeyProvider supplies the Token Receivers' verification key.
type BeaconKeyProvider interface {
	ReceiverKey() (string, error)
}

// SetBeacons enables injection of TS_BEACON_KEY.
func (s *Service) SetBeacons(p BeaconKeyProvider) { s.beacons = p }

func declaresEnv(m models.SensorManifest, name string) bool {
	for _, v := range m.Deployment.EnvVars {
		if v.Name == name {
			return true
		}
	}
	return false
}

// maxManifestBytes bounds registry responses; real manifests are a few KB,
// Sigstore bundles under 10 KB.
const (
	maxManifestBytes = 1 << 20
	maxBundleBytes   = 1 << 20
)

var (
	sensorIDPattern = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)
	versionPattern  = regexp.MustCompile(`^v?\d+\.\d+\.\d+$`)
)

// AllowUnpinnedImages permits manifests without image digests (development).
func (s *Service) AllowUnpinnedImages(allow bool) { s.allowUnpinned = allow }

func NewService(store Store, catalogSvc *catalog.Service) *Service {
	return &Service{
		store:   store,
		catalog: catalogSvc,
		cache:   make(map[string]models.SensorManifest),
	}
}

// --- DTOs ---

type DeployableSensor struct {
	SensorID  string                `json:"sensorId"`
	EnvValues map[string]string     `json:"envValues"`
	Manifest  models.SensorManifest `json:"manifest"`
}

type PreviewRequest struct {
	HubEndpoint string             `json:"hubEndpoint"`
	HubKey      string             `json:"hubKey"`
	Sensors     []DeployableSensor `json:"sensors"`
}

// --- MANIFEST FETCHING ---

func (s *Service) FetchManifestBytes(currentHubVersion string) ([]byte, error) {
	manifests, err := s.fetchStrictCatalogManifests(currentHubVersion)
	if err != nil {
		return nil, err
	}
	return json.Marshal(manifests)
}

func (s *Service) fetchStrictCatalogManifests(currentHubVersion string) ([]models.SensorManifest, error) {
	registryURL, err := s.store.GetConfigValue("registry_url")
	if err != nil || registryURL == "" {
		return nil, fmt.Errorf("registry_url is not configured in database")
	}

	index := s.catalog.GetIndex()
	if index == nil {
		if err := s.catalog.RefreshIndex(); err != nil {
			// Suppressed log spam when registry is down
		}
		index = s.catalog.GetIndex()
	}

	if index == nil {
		return nil, fmt.Errorf("registry unreachable and no local index cache available")
	}

	var result []models.SensorManifest

	for _, sensor := range index.Sensors {
		targetVersion, err := s.catalog.GetLatestCompatibleVersion(sensor.ID, currentHubVersion)
		if err != nil || targetVersion == "" {
			log.Printf("[WARNING] No compatible version found for sensor %s", sensor.ID)
			continue
		}

		cacheKey := sensor.ID + "-v" + targetVersion
		s.mu.RLock()
		cached, ok := s.cache[cacheKey]
		s.mu.RUnlock()

		if ok {
			result = append(result, cached)
			continue
		}

		manifest, fetchErr := s.fetchManifest(registryURL, sensor.ID, strings.TrimPrefix(targetVersion, "v"))
		if fetchErr != nil {
			log.Printf("[WARNING] Skipping %s v%s: %v", sensor.ID, targetVersion, fetchErr)
			continue
		}

		s.mu.Lock()
		s.cache[cacheKey] = manifest
		s.mu.Unlock()

		result = append(result, manifest)
	}

	return result, nil
}

func (s *Service) FetchSpecificManifest(sensorID, targetVersion string) (*models.SensorManifest, error) {
	// Both values end up in a registry URL; reject anything that is not a
	// plain identifier / semver so they cannot traverse the registry host.
	if !sensorIDPattern.MatchString(sensorID) {
		return nil, fmt.Errorf("invalid sensor id %q", sensorID)
	}
	if !versionPattern.MatchString(targetVersion) {
		return nil, fmt.Errorf("invalid version %q", targetVersion)
	}
	cleanVersion := strings.TrimPrefix(targetVersion, "v")

	registryURL, err := s.store.GetConfigValue("registry_url")
	if err != nil || registryURL == "" {
		return nil, fmt.Errorf("registry_url is not configured in database")
	}

	cacheKey := sensorID + "-v" + cleanVersion
	s.mu.RLock()
	cached, ok := s.cache[cacheKey]
	s.mu.RUnlock()

	if ok {
		return &cached, nil
	}

	specific, err := s.fetchManifest(registryURL, sensorID, cleanVersion)
	if err != nil {
		log.Printf("[ERROR] FetchSpecificManifest %s v%s: %v", sensorID, cleanVersion, err)
		return nil, err
	}

	s.mu.Lock()
	s.cache[cacheKey] = specific
	s.mu.Unlock()

	return &specific, nil
}

// fetchManifest downloads one versioned manifest and, when a verifier is set,
// its Sigstore bundle, and checks the signature over the exact bytes before
// decoding them. Only verified bytes are ever decoded, and the manifest must
// name the sensor and version it was requested as.
func (s *Service) fetchManifest(registryURL, sensorID, version string) (models.SensorManifest, error) {
	if !sensorIDPattern.MatchString(sensorID) || !versionPattern.MatchString(version) || strings.HasPrefix(version, "v") {
		return models.SensorManifest{}, fmt.Errorf("invalid sensor %q version %q", sensorID, version)
	}
	sensorName := strings.TrimPrefix(sensorID, "ts-sensor-")
	manifestURL := fmt.Sprintf("%s/%s-v%s.json", strings.TrimRight(registryURL, "/"), sensorName, version)

	body, err := httpGetLimited(manifestURL, maxManifestBytes)
	if err != nil {
		return models.SensorManifest{}, err
	}
	if s.verifier != nil {
		bundle, err := httpGetLimited(manifestURL+signing.BundleSuffix, maxBundleBytes)
		if err != nil {
			return models.SensorManifest{}, fmt.Errorf("no signature for %s: %w", manifestURL, err)
		}
		if err := s.verifier.VerifyManifest(sensorName, version, body, bundle); err != nil {
			return models.SensorManifest{}, fmt.Errorf("%s: %w", manifestURL, err)
		}
	}

	// Same strict decoding everywhere: unknown fields are rejected.
	m, err := security.DecodeManifestStrict(bytes.NewReader(body))
	if err != nil {
		return models.SensorManifest{}, fmt.Errorf("decode %s: %w", manifestURL, err)
	}
	if m.ID != sensorID || strings.TrimPrefix(m.Version, "v") != version {
		return models.SensorManifest{}, fmt.Errorf("manifest identity mismatch: requested %s v%s, got %s v%s", sensorID, version, m.ID, m.Version)
	}
	return m, nil
}

func httpGetLimited(url string, limit int64) ([]byte, error) {
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d from %s", resp.StatusCode, url)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > limit {
		return nil, fmt.Errorf("%s is larger than %d bytes", url, limit)
	}
	return body, nil
}

// --- GENERATION LOGIC ---

// NodeKeyPlaceholder replaces the node key in compose files rendered for the
// dashboard: keys are stored hashed, so the Hub cannot embed the real one.
const NodeKeyPlaceholder = "__REPLACE_WITH_NODE_API_KEY__"

// GetNodeCompose renders the deployment for the node that owns token. The
// caller must already have authenticated the token.
func (s *Service) GetNodeCompose(token, hostFallback string, currentHubVersion string) ([]byte, error) {
	nodeID, err := s.store.GetNodeByKey(token)
	if err != nil || nodeID == "" {
		return nil, fmt.Errorf("unauthorized")
	}
	return s.renderNodeCompose(nodeID, token, hostFallback, currentHubVersion)
}

// GetNodeComposeForDashboard renders a node's deployment for manual installs,
// with NodeKeyPlaceholder in place of the key.
func (s *Service) GetNodeComposeForDashboard(nodeID, hostFallback, currentHubVersion string) ([]byte, error) {
	return s.renderNodeCompose(nodeID, NodeKeyPlaceholder, hostFallback, currentHubVersion)
}

func (s *Service) renderNodeCompose(nodeID, nodeKey, hostFallback string, currentHubVersion string) ([]byte, error) {
	nodeDetails, err := s.store.GetNodeDetails(nodeID)
	if err != nil {
		return nil, fmt.Errorf("failed_to_load")
	}

	hubEndpoint, err := s.store.GetConfigValue("hub_endpoint")
	if err != nil || hubEndpoint == "" {
		hubEndpoint = hostFallback
	}

	effectiveRevision := node.GenerateRevisionHash(nodeDetails.InstalledSensors, s.catalog, currentHubVersion)
	if effectiveRevision != nodeDetails.DesiredRevision {
		if err := s.store.SetNodeDesiredRevision(nodeID, effectiveRevision); err != nil {
			return nil, fmt.Errorf("failed_to_allocate")
		}
	}

	// Auto-reconcile empty nodes since they have no sensors to report back via heartbeats
	if len(nodeDetails.InstalledSensors) == 0 && nodeDetails.HasPendingConfig {
		_ = s.store.ApplyNodeRevision(nodeID, effectiveRevision)
	}

	var finalCompose composeEngine.ComposeFile
	portOwner := map[int]string{}

	for _, sensor := range nodeDetails.InstalledSensors {
		targetVersion := sensor.DeployedVersion
		if targetVersion == "" {
			targetVersion, _ = s.catalog.GetLatestCompatibleVersion(sensor.ID, currentHubVersion)

			// Lock the resolved version in the database so it doesn't float with the catalog
			if targetVersion != "" {
				_ = s.store.SetNodeSensorDeployedVersion(nodeID, sensor.ID, targetVersion)
			}
		}

		manifestPtr, err := s.FetchSpecificManifest(sensor.ID, targetVersion)
		if err != nil || manifestPtr == nil {
			// A configured sensor that cannot be rendered must fail the whole
			// bundle: silently skipping it would make `apply` tear the running
			// decoy down (--remove-orphans) and leave the node undefended.
			log.Printf("[ERROR] Manifest for sensor %s (v%s) unavailable: %v", sensor.ID, targetVersion, err)
			return nil, fmt.Errorf("manifest_unavailable: %s %s", sensor.ID, versionLabel(targetVersion))
		}
		manifest := *manifestPtr

		// The Hub will strictly wait for evaluateNodeSyncState to verify the new hash before considering this version deployed!
		if valErr := security.ValidateManifest(manifest); valErr != nil {
			return nil, fmt.Errorf("invalid_manifest: %w", valErr)
		}
		if !s.allowUnpinned {
			if pinErr := security.RequirePinnedImages(manifest); pinErr != nil {
				return nil, fmt.Errorf("invalid_manifest: %w", pinErr)
			}
		}

		if manifest.Version != "" {
			reqVer := strings.TrimSpace(manifest.Version)
			if !strings.HasPrefix(reqVer, "v") {
				reqVer = "v" + reqVer
			}
			curVer := strings.TrimSpace(currentHubVersion)
			if !strings.HasPrefix(curVer, "v") {
				curVer = "v" + curVer
			}

			if semver.IsValid(reqVer) && semver.Major(curVer) != semver.Major(reqVer) {
				log.Printf("[ERROR] Sensor %s (v%s) is incompatible with Hub (v%s) - Major versions must match", sensor.ID, reqVer, curVer)
				return nil, fmt.Errorf("incompatible_sensor: %s (v%s) requires a matching Hub Major version", sensor.ID, reqVer)
			}
		}

		userVars := make(map[string]string)
		for k, v := range sensor.EnvVars {
			switch val := v.(type) {
			case string:
				userVars[k] = val
			case bool, float64:
				userVars[k] = fmt.Sprint(val)
			}
		}

		sysVars := map[string]string{
			"TS_HUB_ENDPOINT": hubEndpoint,
			"TS_HUB_KEY":      nodeKey,
			"TS_SENSOR_ID":    sensor.ID,
			"TS_TEST_MODE":    "false",
		}
		if effectiveRevision != "" {
			sysVars["TS_CONFIG_REV"] = effectiveRevision
		}
		// Decoys that hash captured passwords get this node's capture key (a
		// per-node key derived from the Hub's master), so the Hub can match
		// their HMACs against honeytokens; File Canary instances get the
		// credential to plant in their lures.
		if s.honeytokens != nil {
			if declaresEnv(manifest, "TS_CAPTURE_HASH_KEY") {
				key, err := s.honeytokens.NodeCaptureKey(nodeID)
				if err != nil {
					return nil, fmt.Errorf("capture_key: %w", err)
				}
				sysVars["TS_CAPTURE_HASH_KEY"] = key
			}
			if declaresEnv(manifest, "TS_HONEYTOKEN") {
				tok, err := s.honeytokens.TokenFor(nodeID, sensor.ID)
				if err != nil {
					return nil, fmt.Errorf("honeytoken: %w", err)
				}
				sysVars["TS_HONEYTOKEN"] = tok.Username + ":" + tok.Secret
			}
		}

		if s.beacons != nil && declaresEnv(manifest, "TS_BEACON_KEY") {
			key, err := s.beacons.ReceiverKey()
			if err != nil {
				return nil, fmt.Errorf("beacon_key: %w", err)
			}
			sysVars["TS_BEACON_KEY"] = key
		}

		envMap := composeEngine.BuildEnv(manifest, userVars, sysVars)

		// Reject two sensors on the same node binding the same host port. All
		// decoys run in the host network namespace, so a clash crash-loops the
		// container and `apply` would roll the node back.
		for _, p := range listenPortsFromEnv(manifest.Deployment.ListenPortsEnv, envMap) {
			if other, dup := portOwner[p]; dup && other != sensor.ID {
				return nil, fmt.Errorf("port_conflict: sensors %s and %s both bind port %d", other, sensor.ID, p)
			}
			portOwner[p] = sensor.ID
		}

		svcCompose, err := composeEngine.BuildService(sensor.ID, manifest, envMap)
		if err != nil {
			log.Printf("[ERROR] Compose build failed for sensor %s (Node %s): %v", sensor.ID, nodeID, err)
			return nil, fmt.Errorf("build_failed: %w", err)
		}
		finalCompose.Services = append(finalCompose.Services, svcCompose.Services...)
	}

	return yaml.Marshal(&finalCompose)
}

// versionLabel names a sensor version in an error; an empty one means the
// registry has no compatible release of that sensor.
func versionLabel(v string) string {
	if v == "" {
		return "(no compatible release in the registry)"
	}
	return "v" + v
}

// ValidateSensors checks a node's sensor list the way rendering its compose
// would (each sensor has a signed, valid manifest; no two bind the same
// port) without rendering or changing anything. The node service calls it
// before saving a sensor add or edit, so a typo is refused at once instead
// of blocking every later `apply` on that node.
func (s *Service) ValidateSensors(sensors []models.NodeSensor, currentHubVersion string) error {
	portOwner := map[int]string{}
	for _, sensor := range sensors {
		version := sensor.DeployedVersion
		if version == "" && s.catalog != nil {
			version, _ = s.catalog.GetLatestCompatibleVersion(sensor.ID, currentHubVersion)
		}
		if version == "" {
			return fmt.Errorf("manifest_unavailable: %s %s", sensor.ID, versionLabel(version))
		}
		manifestPtr, err := s.FetchSpecificManifest(sensor.ID, version)
		if err != nil || manifestPtr == nil {
			return fmt.Errorf("manifest_unavailable: %s %s", sensor.ID, versionLabel(version))
		}
		manifest := *manifestPtr
		if err := security.ValidateManifest(manifest); err != nil {
			return fmt.Errorf("invalid_manifest: %w", err)
		}
		userVars := make(map[string]string)
		for k, v := range sensor.EnvVars {
			switch val := v.(type) {
			case string:
				userVars[k] = val
			case bool, float64:
				userVars[k] = fmt.Sprint(val)
			}
		}
		envMap := composeEngine.BuildEnv(manifest, userVars, nil)
		for _, p := range listenPortsFromEnv(manifest.Deployment.ListenPortsEnv, envMap) {
			if other, dup := portOwner[p]; dup && other != sensor.ID {
				return fmt.Errorf("port_conflict: sensors %s and %s both bind port %d", other, sensor.ID, p)
			}
			portOwner[p] = sensor.ID
		}
		// The build checks what only exists once env is expanded: dynamic
		// mounts from values like TS_DECOY_FILES must pass the same
		// denylist as at render time (e.g. /run/docker.sock is refused).
		if _, err := composeEngine.BuildService(sensor.ID, manifest, envMap); err != nil {
			return fmt.Errorf("build_failed: %w", err)
		}
	}
	return nil
}

// listenPortsFromEnv extracts the ports a sensor binds, from the resolved values
// of the env vars its manifest declares in listen_ports_env. Each value is a
// comma-separated list whose items are "proto:port" or "port".
func listenPortsFromEnv(envNames []string, envMap map[string]string) []int {
	var ports []int
	for _, name := range envNames {
		for _, item := range strings.Split(envMap[name], ",") {
			item = strings.TrimSpace(item)
			if item == "" {
				continue
			}
			if _, after, ok := strings.Cut(item, ":"); ok {
				item = strings.TrimSpace(after)
			}
			if p, err := strconv.Atoi(item); err == nil && p >= 1 && p <= 65535 {
				ports = append(ports, p)
			}
		}
	}
	return ports
}

func (s *Service) GeneratePreviewCompose(req PreviewRequest) ([]byte, error) {
	var finalCompose composeEngine.ComposeFile

	portOwner := map[int]string{}
	for _, sensor := range req.Sensors {
		if valErr := security.ValidateManifest(sensor.Manifest); valErr != nil {
			log.Printf("[ERROR] Preview manifest validation failed for sensor %s: %v", sensor.SensorID, valErr)
			return nil, fmt.Errorf("invalid_manifest: %w", valErr)
		}

		// Same precedence and reserved-variable rules as real deployments.
		envMap := composeEngine.BuildEnv(sensor.Manifest, sensor.EnvValues, map[string]string{
			"TS_HUB_ENDPOINT": req.HubEndpoint,
			"TS_HUB_KEY":      req.HubKey,
			"TS_SENSOR_ID":    sensor.SensorID,
			"TS_TEST_MODE":    "false",
		})

		// Reject two sensors binding the same host port, mirroring the real
		// node-compose compile so the UI preview surfaces the clash the node
		// sync would later reject (422 port_conflict).
		for _, p := range listenPortsFromEnv(sensor.Manifest.Deployment.ListenPortsEnv, envMap) {
			if other, dup := portOwner[p]; dup && other != sensor.SensorID {
				return nil, fmt.Errorf("port_conflict: sensors %s and %s both bind port %d", other, sensor.SensorID, p)
			}
			portOwner[p] = sensor.SensorID
		}

		svcCompose, err := composeEngine.BuildService(sensor.SensorID, sensor.Manifest, envMap)
		if err != nil {
			log.Printf("[ERROR] Compose preview build failed for sensor %s: %v", sensor.SensorID, err)
			return nil, fmt.Errorf("build_failed: %w", err)
		}
		finalCompose.Services = append(finalCompose.Services, svcCompose.Services...)
	}

	return yaml.Marshal(&finalCompose)
}
