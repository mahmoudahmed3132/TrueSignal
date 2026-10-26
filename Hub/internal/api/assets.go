package api

import (
	"encoding/json"
	"net/http"

	"github.com/truesignal/hub/internal/assets"
)

// AssetStore is the config storage the asset inventory lives in.
type AssetStore interface {
	GetConfigValue(key string) (string, error)
	UpdateConfigValue(key, value string) error
}

type AssetsHandler struct {
	store AssetStore
}

func NewAssetsHandler(store AssetStore) *AssetsHandler {
	return &AssetsHandler{store: store}
}

// ListAssets handles GET /api/v2/assets.
func (h *AssetsHandler) ListAssets(w http.ResponseWriter, r *http.Request) {
	raw, _ := h.store.GetConfigValue(assets.ConfigKey)
	list, err := assets.Decode(raw)
	if err != nil {
		RespondError(w, "Stored asset inventory is unreadable", http.StatusInternalServerError)
		return
	}
	SendJSON(w, http.StatusOK, map[string]any{"assets": list})
}

// ReplaceAssets handles PUT /api/v2/assets: the body replaces the whole
// inventory after validation, so an import is one atomic change.
func (h *AssetsHandler) ReplaceAssets(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Assets []assets.Asset `json:"assets"`
	}
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		RespondError(w, "Invalid request body", http.StatusBadRequest)
		return
	}
	if req.Assets == nil {
		req.Assets = []assets.Asset{}
	}
	list, err := assets.Validate(req.Assets)
	if err != nil {
		RespondError(w, err.Error(), http.StatusBadRequest)
		return
	}
	b, _ := json.Marshal(list)
	if err := h.store.UpdateConfigValue(assets.ConfigKey, string(b)); err != nil {
		RespondError(w, "Database error", http.StatusInternalServerError)
		return
	}
	SendJSON(w, http.StatusOK, map[string]any{"assets": list})
}
