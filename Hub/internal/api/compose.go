package api

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/truesignal/hub/internal/models"
	composesvc "github.com/truesignal/hub/internal/services/compose"
)

type ComposeHandler struct {
	service *composesvc.Service
}

func NewComposeHandler(svc *composesvc.Service) *ComposeHandler {
	return &ComposeHandler{service: svc}
}

// GetNodeCompose generates the official docker-compose.yml for a specific agent
// Authentication: Bearer <API_KEY>
func (h *ComposeHandler) GetNodeCompose(w http.ResponseWriter, r *http.Request) {

	token := r.Header.Get("X-Api-Key")
	if token == "" {
		token = strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	}

	hostFallback := "https://" + r.Host
	yamlData, err := h.service.GetNodeCompose(token, hostFallback, models.HubVersion)
	if err != nil {
		if err.Error() == "unauthorized" {
			RespondError(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		respondComposeError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/x-yaml")
	w.WriteHeader(http.StatusOK)

	// codeql[go/xss] Writing safe JSON/YAML API response.
	// nosemgrep: go.lang.security.audit.xss.no-direct-write-to-responsewriter.no-direct-write-to-responsewriter
	w.Write(yamlData)
}

// GetNodeComposeForDashboard handles GET /api/v2/nodes/{nodeId}/compose for
// manual deployments. Node keys are stored hashed, so the file contains a
// placeholder the operator replaces with the node's key.
func (h *ComposeHandler) GetNodeComposeForDashboard(w http.ResponseWriter, r *http.Request) {
	nodeID := chi.URLParam(r, "nodeId")
	yamlData, err := h.service.GetNodeComposeForDashboard(nodeID, "https://"+r.Host, models.HubVersion)
	if err != nil {
		if err.Error() == "failed_to_load" {
			RespondError(w, "Node not found", http.StatusNotFound)
			return
		}
		respondComposeError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/x-yaml")
	w.WriteHeader(http.StatusOK)
	// codeql[go/xss] Writing safe JSON/YAML API response.
	// nosemgrep: go.lang.security.audit.xss.no-direct-write-to-responsewriter.no-direct-write-to-responsewriter
	w.Write(yamlData)
}

// respondComposeError surfaces why a bundle was refused (unpinned image,
// rejected manifest, unavailable version) so `apply` fails with a reason
// instead of a generic 500. These messages contain no secrets.
func respondComposeError(w http.ResponseWriter, err error) {
	msg := err.Error()
	for _, prefix := range []string{"invalid_manifest", "manifest_unavailable", "incompatible_sensor", "build_failed"} {
		if strings.HasPrefix(msg, prefix) {
			RespondError(w, "Failed to generate compose file: "+msg, http.StatusUnprocessableEntity)
			return
		}
	}
	RespondError(w, "Failed to generate compose file", http.StatusInternalServerError)
}

func (h *ComposeHandler) GenerateCompose(w http.ResponseWriter, r *http.Request) {
	var req composesvc.PreviewRequest

	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		http.Error(w, "Invalid payload: "+err.Error(), http.StatusBadRequest)
		return
	}

	yamlData, err := h.service.GeneratePreviewCompose(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/x-yaml")

	// codeql[go/xss] Writing safe JSON/YAML API response.
	// nosemgrep: go.lang.security.audit.xss.no-direct-write-to-responsewriter.no-direct-write-to-responsewriter
	w.Write(yamlData)
}
