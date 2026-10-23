package catalog

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/mod/semver"
)

type RegistryIndex struct {
	Sensors []struct {
		ID       string `json:"id"`
		Latest   string `json:"latest"`
		Versions []struct {
			V string `json:"v"`
		} `json:"versions"`
	} `json:"sensors"`
}

// maxIndexBytes bounds the registry index response.
const maxIndexBytes = 4 << 20

type Store interface {
	GetConfigValue(key string) (string, error)
}

type Broadcaster interface {
	Broadcast(eventType string, payload interface{})
}

type Service struct {
	store       Store
	broadcaster Broadcaster
	indexCache  *RegistryIndex
	mu          sync.RWMutex
	onChange    func()
	httpClient  *http.Client
}

// NewService starts with no index; the first lookup or RefreshIndex loads it
// from the registry. (A hard-coded bootstrap index previously advertised
// sensor versions that do not exist.)
func NewService(store Store, broadcaster Broadcaster) *Service {
	return &Service{store: store, broadcaster: broadcaster, httpClient: &http.Client{Timeout: 10 * time.Second}}
}

// SetHTTPClient replaces the client used for registry requests (for example
// one that authenticates to a private GitHub registry).
func (s *Service) SetHTTPClient(c *http.Client) { s.httpClient = c }

func (s *Service) SetOnChangeHook(hook func()) {
	s.mu.Lock()
	s.onChange = hook
	s.mu.Unlock()
}

func (s *Service) RefreshIndex() error {
	registryURL, err := s.store.GetConfigValue("registry_url")
	if err != nil || registryURL == "" {
		return fmt.Errorf("registry_url not configured")
	}

	indexURL := strings.TrimRight(registryURL, "/") + "/index.json"
	var idx RegistryIndex

	resp, err := s.httpClient.Get(indexURL)
	if err != nil {
		return fmt.Errorf("sensor registry unreachable: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusTooManyRequests {
		return fmt.Errorf("sensor registry rate limit exceeded")
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("sensor registry returned HTTP %d", resp.StatusCode)
	}

	if err := json.NewDecoder(io.LimitReader(resp.Body, maxIndexBytes)).Decode(&idx); err != nil {
		return err
	}

	s.mu.Lock()
	var oldJSON, newJSON []byte
	if s.indexCache != nil {
		oldJSON, _ = json.Marshal(s.indexCache)
	}
	newJSON, _ = json.Marshal(&idx)

	changed := string(oldJSON) != string(newJSON)
	s.indexCache = &idx

	var hook func()
	if changed {
		hook = s.onChange
	}
	s.mu.Unlock()

	if changed {
		if s.broadcaster != nil {
			s.broadcaster.Broadcast("CATALOG_UPDATED", nil)
		}
		if hook != nil {
			go hook()
		}
	}

	return nil
}

func (s *Service) GetIndex() *RegistryIndex {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.indexCache
}

// GetLatestCompatibleVersion safely calculates the highest image tag for the current Hub version
func (s *Service) GetLatestCompatibleVersion(sensorID string, currentHubVersion string) (string, error) {
	s.mu.RLock()
	idx := s.indexCache
	s.mu.RUnlock()

	if idx == nil {
		if err := s.RefreshIndex(); err != nil {
			// Suppressed log spam when offline
		}
		s.mu.RLock()
		idx = s.indexCache
		s.mu.RUnlock()
	}

	if idx != nil {
		for _, sensor := range idx.Sensors {
			cleanSensorID := strings.TrimPrefix(sensor.ID, "ts-sensor-")
			cleanTargetID := strings.TrimPrefix(sensorID, "ts-sensor-")
			if sensor.ID == sensorID || cleanSensorID == cleanTargetID {
				for i := len(sensor.Versions) - 1; i >= 0; i-- {
					reqVer := strings.TrimSpace(sensor.Versions[i].V)
					if !strings.HasPrefix(reqVer, "v") {
						reqVer = "v" + reqVer
					}
					curVer := strings.TrimSpace(currentHubVersion)
					if !strings.HasPrefix(curVer, "v") {
						curVer = "v" + curVer
					}

					if semver.IsValid(reqVer) && semver.Major(curVer) == semver.Major(reqVer) {
						return sensor.Versions[i].V, nil
					}
				}
				return "", fmt.Errorf("no compatible version found for sensor %s", sensorID)
			}
		}
	}

	return "", fmt.Errorf("sensor %s not found in catalog", sensorID)
}
