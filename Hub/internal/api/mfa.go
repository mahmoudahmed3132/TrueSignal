package api

import (
	"encoding/base64"
	"encoding/json"
	"net/http"

	"github.com/truesignal/hub/internal/services/auth"
	"github.com/truesignal/hub/internal/services/config"
	"rsc.io/qr"
)

// MFAHandler serves admin MFA enrollment and management. Every change needs
// the password again; disabling and regenerating recovery codes also need a
// current code, so a hijacked session cannot add its own authenticator or
// switch MFA off.
type MFAHandler struct {
	service *auth.Service
	Cfg     *config.Config
}

func NewMFAHandler(svc *auth.Service, cfg *config.Config) *MFAHandler {
	return &MFAHandler{service: svc, Cfg: cfg}
}

func sessionToken(r *http.Request) string {
	if c, err := r.Cookie(AuthCookieName); err == nil {
		return c.Value
	}
	return ""
}

// noStore keeps secrets and recovery codes out of browser and proxy caches.
func noStore(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
}

func (h *MFAHandler) respondErr(w http.ResponseWriter, err error) {
	switch err {
	case auth.ErrTooManyRequests:
		RespondError(w, err.Error(), http.StatusTooManyRequests)
	case auth.ErrInvalidPassword, auth.ErrInvalidCode:
		RespondError(w, err.Error(), http.StatusUnauthorized)
	case auth.ErrMFAAlreadyEnabled, auth.ErrMFANotEnabled, auth.ErrNoPendingEnrollment:
		RespondError(w, err.Error(), http.StatusConflict)
	case auth.ErrMFARequiredByPolicy:
		RespondError(w, err.Error(), http.StatusForbidden)
	default:
		RespondError(w, "internal_error", http.StatusInternalServerError)
	}
}

func (h *MFAHandler) Status(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	SendJSON(w, http.StatusOK, h.service.Status(sessionToken(r)))
}

func (h *MFAHandler) Setup(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		RespondError(w, "Invalid request", http.StatusBadRequest)
		return
	}
	e, err := h.service.BeginEnrollment(sessionToken(r), req.Password, GetRealIP(r, h.Cfg.TrustsProxyHeaders(r)))
	if err != nil {
		h.respondErr(w, err)
		return
	}
	resp := map[string]string{"secret": e.Secret, "uri": e.URI}
	// The QR code is rendered here so the UI needs no QR library.
	if code, err := qr.Encode(e.URI, qr.M); err == nil {
		resp["qr"] = "data:image/png;base64," + base64.StdEncoding.EncodeToString(code.PNG())
	}
	noStore(w)
	SendJSON(w, http.StatusOK, resp)
}

func (h *MFAHandler) Enable(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Code string `json:"code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		RespondError(w, "Invalid request", http.StatusBadRequest)
		return
	}
	codes, err := h.service.ConfirmEnrollment(sessionToken(r), req.Code)
	if err != nil {
		h.respondErr(w, err)
		return
	}
	noStore(w)
	SendJSON(w, http.StatusOK, map[string][]string{"recoveryCodes": codes})
}

type passwordAndCode struct {
	Password string `json:"password"`
	Code     string `json:"code"`
}

func decodePasswordAndCode(w http.ResponseWriter, r *http.Request) (passwordAndCode, bool) {
	var req passwordAndCode
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		RespondError(w, "Invalid request", http.StatusBadRequest)
		return req, false
	}
	return req, true
}

func (h *MFAHandler) Disable(w http.ResponseWriter, r *http.Request) {
	req, ok := decodePasswordAndCode(w, r)
	if !ok {
		return
	}
	if err := h.service.DisableMFA(req.Password, req.Code, GetRealIP(r, h.Cfg.TrustsProxyHeaders(r))); err != nil {
		h.respondErr(w, err)
		return
	}
	SendJSON(w, http.StatusOK, map[string]string{"status": "disabled"})
}

func (h *MFAHandler) RecoveryCodes(w http.ResponseWriter, r *http.Request) {
	req, ok := decodePasswordAndCode(w, r)
	if !ok {
		return
	}
	codes, err := h.service.RegenerateRecoveryCodes(req.Password, req.Code, GetRealIP(r, h.Cfg.TrustsProxyHeaders(r)))
	if err != nil {
		h.respondErr(w, err)
		return
	}
	noStore(w)
	SendJSON(w, http.StatusOK, map[string][]string{"recoveryCodes": codes})
}
