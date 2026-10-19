package composesvc_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/truesignal/hub/internal/catalog"
	"github.com/truesignal/hub/internal/models"
	composesvc "github.com/truesignal/hub/internal/services/compose"
)

type MockStore struct {
	RegistryURL           string
	AssignedRevision      string
	ShouldFailSetRevision bool
}

func (m *MockStore) GetConfigValue(key string) (string, error) {
	if key == "registry_url" {
		return m.RegistryURL, nil
	}
	if key == "hub_endpoint" {
		return "http://localhost:8080", nil
	}
	return "", nil
}

func (m *MockStore) GetNodeByKey(token string) (string, error) {
	return "node-1", nil
}

func (m *MockStore) GetNodeDetails(nodeID string) (*models.Node, error) {
	return &models.Node{
		ID: "node-1",
		InstalledSensors: []models.NodeSensor{
			{ID: "ts-sensor-test"},
		},
		DesiredRevision: "old_revision",
	}, nil
}

func (m *MockStore) SetNodeDesiredRevision(nodeID, rev string) error {
	if m.ShouldFailSetRevision {
		return fmt.Errorf("simulated database lock timeout")
	}
	m.AssignedRevision = rev
	return nil
}

func (m *MockStore) SetNodeSensorDeployedVersion(nodeID, sensorID, version string) error {
	return nil
}

func (m *MockStore) ApplyNodeRevision(nodeID, revision string) error {
	return nil
}

func TestComposeSmartVersionSelection(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/index.json" {
			json.NewEncoder(w).Encode(map[string]interface{}{
				"sensors": []map[string]interface{}{
					{
						"id":     "ts-sensor-test",
						"latest": "2.0.0",
						"versions": []map[string]string{
							{"v": "1.0.0"},
							{"v": "2.0.0"},
							{"v": "2.5.0"},
							{"v": "3.0.0"},
						},
					},
				},
			})
			return
		}

		// Mock responses for the requested versions
		version := r.URL.Path[len("/test-v") : len(r.URL.Path)-5] // Extract version from path
		if version == "" {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		json.NewEncoder(w).Encode(map[string]interface{}{
			"id":      "ts-sensor-test",
			"version": version,
			"deployment": map[string]interface{}{
				"image_repository": "test",
				"image_tag":        version,
				"image_digest":     testDigest,
			},
		})
	}))
	defer ts.Close()

	store := &MockStore{RegistryURL: ts.URL}
	catSvc := catalog.NewService(store, nil)
	catSvc.RefreshIndex() // explicitly refresh
	svc := composesvc.NewService(store, catSvc)

	// VERSIONING ARCHITECTURE EXPLANATION (SENSOR REGISTRY):
	// The Compose service automatically parses the registry's index.json and steps backwards
	// through the versions array to find the absolute highest sensor image tag that is compatible
	// with the currently executing Hub. If the Hub's API is too old for the absolute latest
	// sensor release, it gracefully injects the previous compatible tag into the docker-compose YAML.
	t.Run("Perfect Match Resolution (Hub API 2)", func(t *testing.T) {
		// Hub API 2 should select v2.5.0
		yamlData, err := svc.GetNodeCompose("dummy", "http://localhost", "2.0.0")
		if err != nil {
			t.Fatalf("Expected success, got error: %v", err)
		}

		if !contains(yamlData, "image: test:2.5.0") {
			t.Errorf("Expected to deploy v2.5.0, got yaml:\n%s", string(yamlData))
		}
	})

	// An installed sensor with no deployable version must fail the bundle.
	// Returning a compose without it would make `apply --remove-orphans`
	// silently tear down the running decoy.
	t.Run("Incompatible Hub API 4 fails closed", func(t *testing.T) {
		_, err := svc.GetNodeCompose("dummy", "http://localhost", "4.0.0")
		if err == nil || !strings.Contains(err.Error(), "manifest_unavailable") {
			t.Fatalf("Expected manifest_unavailable, got: %v", err)
		}
	})

	t.Run("No Compatible Version Found fails closed", func(t *testing.T) {
		_, err := svc.GetNodeCompose("dummy", "http://localhost", "0.0.0")
		if err == nil || !strings.Contains(err.Error(), "manifest_unavailable") {
			t.Fatalf("Expected manifest_unavailable, got: %v", err)
		}
	})

	t.Run("Whitespace Robust Parsing", func(t *testing.T) {
		yamlData, err := svc.GetNodeCompose("dummy", "http://localhost", "  2.0.0  ")
		if err != nil {
			t.Fatalf("Expected success, got error: %v", err)
		}
		if !contains(yamlData, "image: test:2.5.0") {
			t.Errorf("Expected fallback to v2.5.0, got yaml:\n%s", string(yamlData))
		}
	})

	t.Run("Network Cache Fallback on 502", func(t *testing.T) {
		// First, do a successful fetch to populate the cache
		_, _ = svc.GetNodeCompose("dummy", "http://localhost", "2.0.0")

		// Now break the registry URL so the next fetch fails completely
		store.RegistryURL = "http://localhost:1" // guaranteed connection refused

		// Attempt to fetch again. The network will fail, but the cache should save the day!
		yamlData, err := svc.GetNodeCompose("dummy", "http://localhost", "2.0.0")
		if err != nil {
			t.Fatalf("Expected cache fallback success, got error: %v", err)
		}

		if !contains(yamlData, "image: test:2.5.0") {
			t.Errorf("Expected cached fallback to v2.5.0, got yaml:\n%s", string(yamlData))
		}
	})
}

var testDigest = "sha256:" + strings.Repeat("a", 64)

func contains(b []byte, s string) bool {
	return strings.Contains(string(b), s)
}

func TestGetNodeComposeSynchronousSync(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/index.json" {
			json.NewEncoder(w).Encode(map[string]interface{}{
				"sensors": []map[string]interface{}{
					{
						"id":       "ts-sensor-test",
						"latest":   "1.0.0",
						"versions": []map[string]string{{"v": "1.0.0"}},
					},
				},
			})
			return
		}
		if r.URL.Path == "/test-v1.0.0.json" {
			json.NewEncoder(w).Encode(map[string]interface{}{
				"id":      "ts-sensor-test",
				"version": "1.0.0",
				"deployment": map[string]interface{}{
					"image_repository": "test-image",
					"image_tag":        "v1.0.0",
					"image_digest":     testDigest,
				},
			})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	store := &MockStore{RegistryURL: ts.URL}
	catSvc := catalog.NewService(store, nil)
	svc := composesvc.NewService(store, catSvc)

	// Refresh index to simulate worker background state
	catSvc.RefreshIndex()

	yamlData, err := svc.GetNodeCompose("node-1", "http://fallback.com", "v1.0.0")
	if err != nil {
		t.Fatalf("GetNodeCompose failed: %v", err)
	}
	if !contains(yamlData, "image: test-image:v1.0.0@"+testDigest) {
		t.Errorf("expected digest-pinned image in compose, got:\n%s", yamlData)
	}

	// Verify that GetNodeCompose calculated a new hash and explicitly synchronized it!
	if store.AssignedRevision == "" || store.AssignedRevision == "old_revision" {
		t.Fatalf("Expected DesiredRevision to be dynamically assigned new hash, got: %v", store.AssignedRevision)
	}
}

func TestComposeSetDesiredRevisionErrorHandling(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/index.json" {
			json.NewEncoder(w).Encode(map[string]interface{}{
				"sensors": []map[string]interface{}{
					{
						"id":       "ts-sensor-test",
						"latest":   "1.0.0",
						"versions": []map[string]string{{"v": "1.0.0"}},
					},
				},
			})
			return
		}
		if r.URL.Path == "/test-v1.0.0.json" {
			json.NewEncoder(w).Encode(map[string]interface{}{
				"id":      "ts-sensor-test",
				"version": "1.0.0",
				"deployment": map[string]interface{}{
					"image_repository": "test-image",
					"image_tag":        "v1.0.0",
					"image_digest":     testDigest,
				},
			})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	// Simulate database failure
	store := &MockStore{RegistryURL: ts.URL, ShouldFailSetRevision: true}
	catSvc := catalog.NewService(store, nil)
	svc := composesvc.NewService(store, catSvc)

	catSvc.RefreshIndex()

	_, err := svc.GetNodeCompose("node-1", "http://fallback.com", "v1.0.0")
	if err == nil || !strings.Contains(err.Error(), "failed_to_allocate") {
		t.Fatalf("Expected failed_to_allocate error to cascade up, got: %v", err)
	}
}

func TestCompose_RejectsUnpinnedImagesUnlessAllowed(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/index.json" {
			json.NewEncoder(w).Encode(map[string]interface{}{
				"sensors": []map[string]interface{}{{"id": "ts-sensor-test", "latest": "1.0.0", "versions": []map[string]string{{"v": "1.0.0"}}}},
			})
			return
		}
		json.NewEncoder(w).Encode(map[string]interface{}{
			"id": "ts-sensor-test", "version": "1.0.0",
			"deployment": map[string]interface{}{"image_repository": "test-image", "image_tag": "v1.0.0"},
		})
	}))
	defer ts.Close()

	store := &MockStore{RegistryURL: ts.URL}
	catSvc := catalog.NewService(store, nil)
	catSvc.RefreshIndex()
	svc := composesvc.NewService(store, catSvc)

	if _, err := svc.GetNodeCompose("node-1", "http://x", "v1.0.0"); err == nil || !strings.Contains(err.Error(), "not pinned") {
		t.Fatalf("expected unpinned image to be rejected, got %v", err)
	}
	svc.AllowUnpinnedImages(true)
	if _, err := svc.GetNodeCompose("node-1", "http://x", "v1.0.0"); err != nil {
		t.Fatalf("expected unpinned image to be allowed in dev mode, got %v", err)
	}
}

func TestFetchSpecificManifest_RejectsPathInjection(t *testing.T) {
	store := &MockStore{RegistryURL: "http://127.0.0.1:1"}
	svc := composesvc.NewService(store, catalog.NewService(store, nil))
	for _, tc := range [][2]string{{"../../etc", "1.0.0"}, {"ts-sensor-test", "1.0.0/../../x"}, {"ts-sensor-test", ""}} {
		if _, err := svc.FetchSpecificManifest(tc[0], tc[1]); err == nil || !strings.Contains(err.Error(), "invalid") {
			t.Errorf("expected rejection for %v, got %v", tc, err)
		}
	}
}
