package node_test

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/truesignal/hub/internal/catalog"
	"github.com/truesignal/hub/internal/models"
	"github.com/truesignal/hub/internal/services/node"
)

type MockNodeStore struct {
	nodes           map[string]*models.Node
	DeployedUpdates map[string]string // Tracks bumped DeployedVersions for assertion
}

func NewMockNodeStore() *MockNodeStore {
	return &MockNodeStore{
		nodes:           make(map[string]*models.Node),
		DeployedUpdates: make(map[string]string),
	}
}

func (m *MockNodeStore) GetNodes() ([]models.Node, error) {
	var result []models.Node
	for _, n := range m.nodes {
		result = append(result, *n)
	}
	return result, nil
}

func (m *MockNodeStore) GetNodeDetails(nodeID string) (*models.Node, error) {
	if n, ok := m.nodes[nodeID]; ok {
		return n, nil
	}
	return nil, nil
}

func (m *MockNodeStore) SetNodeSensorDeployedVersion(nodeID, sensorID, version string) error {
	m.DeployedUpdates[nodeID+":"+sensorID] = version
	return nil
}

func (m *MockNodeStore) GetConfigValue(key string) (string, error) {
	return "", nil
}

// Unused methods required by interface
func (m *MockNodeStore) CreateNode(alias, tags string) (string, string, error) { return "", "", nil }
func (m *MockNodeStore) UpdateNodeMeta(nodeID, alias, tags string, publicIP, privateIP *string) error {
	return nil
}
func (m *MockNodeStore) AddSensorToNode(nodeID, sensorID, customName string, configValues map[string]interface{}) error {
	return nil
}
func (m *MockNodeStore) UpdateNodeSensor(nodeID, sensorID, customName string, configValues map[string]interface{}) error {
	return nil
}
func (m *MockNodeStore) RemoveNodeSensor(nodeID, sensorID string) error { return nil }
func (m *MockNodeStore) SetNodePendingConfig(nodeID string) error       { return nil }
func (m *MockNodeStore) ClearNodePendingConfig(nodeID string) error     { return nil }
func (m *MockNodeStore) DeleteNode(nodeID string) error                 { return nil }
func (m *MockNodeStore) RotateNodeKey(nodeID string) (string, error)    { return "ts_key_new", nil }

type MockNodeBroadcaster struct{}

func (m *MockNodeBroadcaster) Broadcast(eventType string, payload interface{}) {}

func TestGetNodeDetailsStrictHashMatch(t *testing.T) {
	responseIndex := map[string]interface{}{
		"sensors": []map[string]interface{}{
			{
				"id":     "ts-sensor-test",
				"latest": "v2.0.0", // Latest version available is v2.0.0
				"versions": []map[string]interface{}{
					{"v": "v2.0.0"},
				},
			},
		},
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(responseIndex)
	}))
	defer ts.Close()

	catStore := &CatalogStore{url: ts.URL}
	catSvc := catalog.NewService(catStore, nil)
	catSvc.RefreshIndex() // Hydrate catalog

	store := NewMockNodeStore()
	store.nodes["node-1"] = &models.Node{
		ID:             "node-1",
		ActiveRevision: "old_revision_hash",
		InstalledSensors: []models.NodeSensor{
			{
				ID:              "ts-sensor-test",
				DeployedVersion: "v1.0.0", // Older version so it triggers UpdateAvailable
			},
		},
	}

	svc := node.NewService(store, &MockNodeBroadcaster{}, catSvc)

	// Call GetNodeDetails - ActiveRevision ("old_revision_hash") DOES NOT match newly generated hash!
	nodeData, err := svc.GetNodeDetails("node-1")
	if err != nil {
		t.Fatalf("GetNodeDetails failed: %v", err)
	}

	// Because hashes did not match, it MUST NOT auto-bump the DeployedVersion in the database
	if val, ok := store.DeployedUpdates["node-1:ts-sensor-test"]; ok {
		t.Fatalf("Expected DeployedVersion to REMAIN v1.0.0, but it aggressively auto-bumped to %s", val)
	}

	// Now we spoof a successful Edge Node heartbeat that updates ActiveRevision to perfectly match the newest hash
	newHash := node.GenerateRevisionHash(store.nodes["node-1"].InstalledSensors, catSvc, models.HubVersion)
	store.nodes["node-1"].ActiveRevision = newHash

	// GetNodeDetails should correctly return UpdateAvailable flag.
	if len(nodeData.InstalledSensors) > 0 && !nodeData.InstalledSensors[0].UpdateAvailable {
		t.Fatalf("Expected UpdateAvailable to be true")
	}
}

type CatalogStore struct{ url string }

func (c *CatalogStore) GetConfigValue(key string) (string, error) {
	if key == "registry_url" {
		return c.url, nil
	}
	return "", nil
}

func TestSensorChangesAreValidatedBeforeSaving(t *testing.T) {
	store := NewMockNodeStore()
	store.nodes["node-1"] = &models.Node{ID: "node-1", InstalledSensors: []models.NodeSensor{
		{ID: "ts-sensor-remote-access-decoy", EnvVars: map[string]interface{}{"TS_SERVICES": "ssh:2222"}, DeployedVersion: "2.0.1"},
	}}
	svc := node.NewService(store, &MockNodeBroadcaster{}, nil)
	var seen [][]models.NodeSensor
	svc.SetSensorValidator(func(s []models.NodeSensor) error {
		seen = append(seen, s)
		for _, x := range s {
			if x.EnvVars["TS_DECOY_PORTS"] == "2222" {
				return errors.New("port_conflict: 2222")
			}
		}
		return nil
	})

	err := svc.AddSensor("node-1", "ts-sensor-tcp-tarpit", "Tarpit", map[string]interface{}{"TS_DECOY_PORTS": "2222"})
	if !errors.Is(err, node.ErrInvalidSensorConfig) || !strings.Contains(err.Error(), "port_conflict") {
		t.Fatalf("clash: err = %v", err)
	}
	if len(seen) != 1 || len(seen[0]) != 2 {
		t.Fatalf("validator saw %v", seen)
	}
	if err := svc.AddSensor("node-1", "ts-sensor-remote-access-decoy", "dup", nil); !errors.Is(err, node.ErrSensorExists) {
		t.Fatalf("duplicate: err = %v", err)
	}
	// An edit validates the node with the new values in place of the old.
	if err := svc.EditSensor("node-1", "ts-sensor-remote-access-decoy", "SSH", map[string]interface{}{"TS_DECOY_PORTS": "2222"}); !errors.Is(err, node.ErrInvalidSensorConfig) {
		t.Fatalf("edit: err = %v", err)
	}
	if err := svc.AddSensor("node-1", "ts-sensor-tcp-tarpit", "Tarpit", map[string]interface{}{"TS_DECOY_PORTS": "2323"}); err != nil {
		t.Fatalf("valid add: %v", err)
	}
	if err := svc.AddSensor("node-missing", "ts-sensor-tcp-tarpit", "x", nil); err == nil {
		t.Fatal("missing node accepted")
	}
}
