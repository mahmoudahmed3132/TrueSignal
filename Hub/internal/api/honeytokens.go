package api

import (
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
// files themselves).
func (h *HoneytokenHandler) ListHoneytokens(w http.ResponseWriter, r *http.Request) {
	tokens, err := h.service.List()
	if err != nil {
		RespondError(w, "Database error", http.StatusInternalServerError)
		return
	}
	SendJSON(w, http.StatusOK, tokens)
}
