package api

import (
	"database/sql"
	"encoding/json"
	"errors"
	"log"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/truesignal/hub/internal/services/node"
)

// CreateNode handles UI-first node creation
// Route: POST /api/v2/nodes
type NodeHandler struct {
	service *node.Service
}

func NewNodeHandler(svc *node.Service) *NodeHandler {
	return &NodeHandler{service: svc}
}

func (h *NodeHandler) CreateNode(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Alias string   `json:"alias"`
		Tags  []string `json:"tags"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		RespondError(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.Alias == "" {
		RespondError(w, "Alias is required", http.StatusBadRequest)
		return
	}

	nodeID, apiKey, err := h.service.CreateNode(req.Alias, req.Tags)
	if err != nil {
		RespondError(w, "Failed to create node in database", http.StatusInternalServerError)
		return
	}

	SendJSON(w, http.StatusCreated, map[string]interface{}{
		"nodeId": nodeID,
		"apiKey": apiKey,
		"alias":  req.Alias,
	})
}

// UpdateNode handles UI requests to edit a Node's metadata
// Route: PATCH /api/v2/nodes/{id}
func (h *NodeHandler) UpdateNode(w http.ResponseWriter, r *http.Request) {
	nodeID := chi.URLParam(r, "nodeId")

	var req struct {
		Alias     string   `json:"alias"`
		Tags      []string `json:"tags"`
		PublicIP  *string  `json:"publicIp"`
		PrivateIP *string  `json:"privateIp"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		RespondError(w, "Invalid payload", http.StatusBadRequest)
		return
	}

	if req.Alias == "" {
		RespondError(w, "Alias cannot be empty", http.StatusBadRequest)
		return
	}

	if err := h.service.UpdateNode(nodeID, req.Alias, req.Tags, req.PublicIP, req.PrivateIP); err != nil {
		RespondError(w, "Failed to update node", http.StatusInternalServerError)
		return
	}

	SendJSON(w, http.StatusOK, map[string]string{"status": "success"})
}

// GetNodes handles GET /api/v2/nodes
func (h *NodeHandler) GetNodes(w http.ResponseWriter, r *http.Request) {
	nodes, err := h.service.GetNodes()
	if err != nil {
		log.Printf("[ERROR] GetNodes failed: %v\n", err)
		RespondError(w, "Failed to fetch fleet nodes", http.StatusInternalServerError)
		return
	}

	SendJSON(w, http.StatusOK, nodes)
}

// GetNodeDetails handles GET /api/v2/nodes/{id}
func (h *NodeHandler) GetNodeDetails(w http.ResponseWriter, r *http.Request) {
	nodeID := chi.URLParam(r, "nodeId")

	node, err := h.service.GetNodeDetails(nodeID)
	if err != nil {
		RespondError(w, "Node not found", http.StatusNotFound)
		return
	}

	SendJSON(w, http.StatusOK, map[string]interface{}{
		"nodeId":             node.ID,
		"alias":              node.Alias,
		"activeRevision":     node.ActiveRevision,
		"desiredRevision":    node.DesiredRevision,
		"publicIp":           node.PublicIP,
		"privateIp":          node.PrivateIP,
		"tags":               node.Tags,
		"hasPendingConfig":   node.HasPendingConfig,
		"hasUpdateAvailable": node.HasUpdateAvailable,
		"lastHeartbeat":      node.LastHeartbeat,
		"status":             node.Status,
		"installedSensors":   node.InstalledSensors,
	})
}

// AddNodeSensor handles POST /api/v2/nodes/{id}/sensors
func (h *NodeHandler) AddNodeSensor(w http.ResponseWriter, r *http.Request) {
	nodeID := chi.URLParam(r, "nodeId")

	var req struct {
		SensorID     string                 `json:"sensorId"`
		CustomName   string                 `json:"customName"`
		ConfigValues map[string]interface{} `json:"configValues"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		RespondError(w, "Invalid payload", http.StatusBadRequest)
		return
	}

	if req.SensorID == "" || req.CustomName == "" {
		RespondError(w, "sensorId and customName are required", http.StatusBadRequest)
		return
	}

	if err := h.service.AddSensor(nodeID, req.SensorID, req.CustomName, req.ConfigValues); err != nil {
		respondSensorChangeError(w, err, "Failed to add sensor")
		return
	}

	SendJSON(w, http.StatusOK, map[string]string{"status": "success", "message": "Sensor added, node pending sync"})
}

// EditNodeSensor handles PUT /api/v2/nodes/{id}/sensors/{sensorId}
func (h *NodeHandler) EditNodeSensor(w http.ResponseWriter, r *http.Request) {
	nodeID := chi.URLParam(r, "nodeId")
	sensorID := chi.URLParam(r, "sensorId")

	var req struct {
		CustomName   string                 `json:"customName"`
		ConfigValues map[string]interface{} `json:"configValues"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		RespondError(w, "Invalid payload", http.StatusBadRequest)
		return
	}

	if err := h.service.EditSensor(nodeID, sensorID, req.CustomName, req.ConfigValues); err != nil {
		respondSensorChangeError(w, err, "Failed to update sensor")
		return
	}

	SendJSON(w, http.StatusOK, map[string]string{"status": "success"})
}

// UpgradeNodeSensor handles POST /api/v2/nodes/{id}/sensors/{sensorId}/upgrade
func (h *NodeHandler) UpgradeNodeSensor(w http.ResponseWriter, r *http.Request) {
	nodeID := chi.URLParam(r, "nodeId")
	sensorID := chi.URLParam(r, "sensorId")

	if err := h.service.UpgradeSensor(nodeID, sensorID); err != nil {
		RespondError(w, "Failed to upgrade sensor: "+err.Error(), http.StatusInternalServerError)
		return
	}

	SendJSON(w, http.StatusOK, map[string]string{"status": "success", "message": "Sensor upgraded, node pending sync"})
}

// DeleteNodeSensor handles DELETE /api/v2/nodes/{id}/sensors/{sensorId}
func (h *NodeHandler) DeleteNodeSensor(w http.ResponseWriter, r *http.Request) {
	nodeID := chi.URLParam(r, "nodeId")
	sensorID := chi.URLParam(r, "sensorId")

	if err := h.service.DeleteSensor(nodeID, sensorID); err != nil {
		RespondError(w, "Failed to remove sensor", http.StatusInternalServerError)
		return
	}

	SendJSON(w, http.StatusOK, map[string]string{"status": "success"})
}

// RotateNodeKey handles POST /api/v2/nodes/{id}/rotate-key. The new key is
// returned exactly once; the previous key stops working immediately.
func (h *NodeHandler) RotateNodeKey(w http.ResponseWriter, r *http.Request) {
	nodeID := chi.URLParam(r, "nodeId")

	key, err := h.service.RotateKey(nodeID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			RespondError(w, "Node not found", http.StatusNotFound)
			return
		}
		RespondError(w, "Failed to rotate node key", http.StatusInternalServerError)
		return
	}

	SendJSON(w, http.StatusOK, map[string]string{"nodeId": nodeID, "apiKey": key})
}

// DeleteNode handles DELETE /api/v2/nodes/{id}
func (h *NodeHandler) DeleteNode(w http.ResponseWriter, r *http.Request) {
	nodeID := chi.URLParam(r, "nodeId")

	if err := h.service.DeleteNode(nodeID); err != nil {
		RespondError(w, "Failed to delete node", http.StatusInternalServerError)
		return
	}

	SendJSON(w, http.StatusOK, map[string]string{"status": "success"})
}

// UpgradeNode handles POST /api/v2/nodes/{id}/upgrade
func (h *NodeHandler) UpgradeNode(w http.ResponseWriter, r *http.Request) {
	nodeID := chi.URLParam(r, "nodeId")

	if err := h.service.UpgradeNode(nodeID); err != nil {
		RespondError(w, "Failed to upgrade node: "+err.Error(), http.StatusInternalServerError)
		return
	}

	SendJSON(w, http.StatusOK, map[string]string{"status": "success", "message": "Node upgraded, pending sync"})
}

// GetCurrentNode handles GET /api/v2/nodes/me
// Used by wizard agents authenticated via Bearer token
func (h *NodeHandler) GetCurrentNode(w http.ResponseWriter, r *http.Request) {

	nodeID := NodeIDFromContext(r.Context())

	if nodeID == "" {
		RespondError(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Fetch full node details
	node, err := h.service.GetNodeDetails(nodeID)

	if err != nil {
		RespondError(w, "Node not found", http.StatusNotFound)
		return
	}

	SendJSON(w, http.StatusOK, map[string]interface{}{
		"nodeId":             node.ID,
		"alias":              node.Alias,
		"activeRevision":     node.ActiveRevision,
		"desiredRevision":    node.DesiredRevision,
		"publicIp":           node.PublicIP,
		"privateIp":          node.PrivateIP,
		"tags":               node.Tags,
		"hasPendingConfig":   node.HasPendingConfig,
		"hasUpdateAvailable": node.HasUpdateAvailable,
		"lastHeartbeat":      node.LastHeartbeat,
		"status":             node.Status,
		"installedSensors":   node.InstalledSensors,
	})
}

// respondSensorChangeError maps a refused sensor add/edit: 409 when the
// sensor is already on the node, 422 with the reason when the change would
// break the node's compose (port clash, no signed manifest).
func respondSensorChangeError(w http.ResponseWriter, err error, fallback string) {
	switch {
	case errors.Is(err, node.ErrSensorExists):
		RespondError(w, "This sensor is already installed on the node.", http.StatusConflict)
	case errors.Is(err, node.ErrInvalidSensorConfig):
		RespondError(w, err.Error(), http.StatusUnprocessableEntity)
	default:
		RespondError(w, fallback, http.StatusInternalServerError)
	}
}
