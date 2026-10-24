package api

import (
	"encoding/csv"
	"net/http"

	"github.com/truesignal/hub/internal/models"
)

// HoneytokenLister lists planted honeytokens.
type HoneytokenLister interface {
	List() ([]models.Honeytoken, error)
}

type HoneytokenHandler struct {
	service HoneytokenLister
}

func NewHoneytokenHandler(svc HoneytokenLister) *HoneytokenHandler {
	return &HoneytokenHandler{service: svc}
}

// ListHoneytokens returns every planted honeytoken with where it was planted
// and when it was last used. Secrets are never returned (they are in the lure
// files themselves). ?format=csv returns a watchlist for SIEM lookup files.
func (h *HoneytokenHandler) ListHoneytokens(w http.ResponseWriter, r *http.Request) {
	tokens, err := h.service.List()
	if err != nil {
		RespondError(w, "Database error", http.StatusInternalServerError)
		return
	}
	if r.URL.Query().Get("format") != "csv" {
		SendJSON(w, http.StatusOK, tokens)
		return
	}
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="truesignal-honeytokens.csv"`)
	cw := csv.NewWriter(w)
	cw.Write([]string{"username", "honeytoken_id", "planted_node_id", "planted_sensor_id", "created_at"})
	for _, t := range tokens {
		cw.Write([]string{t.Username, t.ID, t.NodeID, t.SensorID, t.CreatedAt})
	}
	cw.Flush()
}
