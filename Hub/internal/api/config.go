package api

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/truesignal/hub/internal/models"
	"github.com/truesignal/hub/internal/services/config"
	"github.com/truesignal/hub/internal/services/updater"
)

type ConfigHandler struct {
	service *config.Service
	Cfg     *config.Config
	updater *updater.Service
}

func NewConfigHandler(svc *config.Service, cfg *config.Config, upSvc *updater.Service) *ConfigHandler {
	return &ConfigHandler{service: svc, Cfg: cfg, updater: upSvc}
}

func (h *ConfigHandler) GetSetupStatus(w http.ResponseWriter, r *http.Request) {
	requiresSetup, _ := h.service.GetSetupStatus()
	SendJSON(w, http.StatusOK, map[string]bool{"requiresSetup": requiresSetup})
}

func (h *ConfigHandler) CompleteSetup(w http.ResponseWriter, r *http.Request) {
	var req models.SetupPayload
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		RespondError(w, "Invalid payload", http.StatusBadRequest)
		return
	}

	if req.HubEndpoint == "" || req.Password == "" {
		RespondError(w, "Invalid setup parameters. Missing required fields.", http.StatusBadRequest)
		return
	}

	if err := h.service.CompleteSetup(req.Password, req.HubEndpoint, req.SetupToken); err != nil {
		if err.Error() == "invalid_setup_token" {
			RespondError(w, "Invalid setup token. Copy it from the Hub log ([SETUP] line).", http.StatusForbidden)
			return
		}
		if err.Error() == "weak_password" {
			RespondError(w, "Password must be at least 12 characters.", http.StatusBadRequest)
			return
		}
		if err.Error() == "setup_locked" {
			RespondError(w, "Setup is locked by environment configuration.", http.StatusForbidden)
			return
		}
		if err.Error() == "already_setup" {
			RespondError(w, "Setup has already been completed. Unauthorized.", http.StatusForbidden)
			return
		}
		RespondError(w, "Failed to complete setup", http.StatusInternalServerError)
		return
	}

	SendJSON(w, http.StatusOK, map[string]string{"status": "success"})
}

func (h *ConfigHandler) GetConfig(w http.ResponseWriter, r *http.Request) {
	cfg, err := h.service.GetConfig()
	if err != nil {
		RespondError(w, "Failed to fetch config", http.StatusInternalServerError)
		return
	}

	SendJSON(w, http.StatusOK, cfg)
}

func (h *ConfigHandler) UpdateConfig(w http.ResponseWriter, r *http.Request) {
	var req map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		RespondError(w, "Invalid JSON payload", http.StatusBadRequest)
		return
	}

	if err := h.service.UpdateConfig(req); err != nil {
		var verr *config.ValidationError
		if errors.As(err, &verr) {
			RespondError(w, verr.Msg, http.StatusBadRequest)
			return
		}
		RespondError(w, "Database error", http.StatusInternalServerError)
		return
	}

	SendJSON(w, http.StatusOK, map[string]string{"status": "success"})
}

func (h *ConfigHandler) ChangePassword(w http.ResponseWriter, r *http.Request) {
	var req struct {
		CurrentPassword string `json:"currentPassword"`
		NewPassword     string `json:"newPassword"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		RespondError(w, "Invalid payload", http.StatusBadRequest)
		return
	}

	if err := h.service.ChangePassword(req.CurrentPassword, req.NewPassword); err != nil {
		if err.Error() == "password_locked" {
			RespondError(w, "Password is locked by environment configuration.", http.StatusForbidden)
			return
		}
		if err.Error() == "incorrect_password" {
			RespondError(w, "Incorrect current password", http.StatusUnauthorized)
			return
		}
		if err.Error() == "weak_password" {
			RespondError(w, "Password must be at least 12 characters.", http.StatusBadRequest)
			return
		}
		RespondError(w, "Failed to update password", http.StatusInternalServerError)
		return
	}

	clearAuthCookie(w, h.Cfg)

	SendJSON(w, http.StatusOK, map[string]string{"status": "success"})
}

func (h *ConfigHandler) FactoryReset(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Password string `json:"password"`
		// PurgeHoneytokens also deletes planted honeytokens and the capture
		// master key. Lures already on disk then carry credentials the Hub no
		// longer recognises, so remove them first.
		PurgeHoneytokens bool `json:"purgeHoneytokens"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		RespondError(w, "Invalid payload", http.StatusBadRequest)
		return
	}

	ip := GetRealIP(r, h.Cfg.TrustProxy)
	dryrun := r.URL.Query().Get("dryrun") == "true"

	if dryrun {
		stats, err := h.service.FactoryResetDryRun(req.Password, req.PurgeHoneytokens)
		if err != nil {
			if err.Error() == "incorrect_password" {
				RespondError(w, "Incorrect password", http.StatusUnauthorized)
				return
			}
			RespondError(w, "Failed to calculate dry run", http.StatusInternalServerError)
			return
		}
		SendJSON(w, http.StatusOK, map[string]interface{}{
			"status": "success",
			"dryrun": true,
			"stats":  stats,
		})
		return
	}

	if err := h.service.FactoryReset(req.Password, ip, req.PurgeHoneytokens); err != nil {
		if err.Error() == "incorrect_password" {
			RespondError(w, "Incorrect password", http.StatusUnauthorized)
			return
		}
		RespondError(w, "Failed to factory reset", http.StatusInternalServerError)
		return
	}

	clearAuthCookie(w, h.Cfg)

	SendJSON(w, http.StatusOK, map[string]string{"status": "success"})
}

func (h *ConfigHandler) GetSystemState(w http.ResponseWriter, r *http.Request) {
	isArmed, _ := h.service.GetSystemState()
	SendJSON(w, http.StatusOK, map[string]bool{"isArmed": isArmed})
}

func (h *ConfigHandler) SetSystemState(w http.ResponseWriter, r *http.Request) {
	var req struct {
		IsArmed bool `json:"isArmed"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		RespondError(w, err.Error(), http.StatusBadRequest)
		return
	}

	if err := h.service.SetSystemState(req.IsArmed); err != nil {
		RespondError(w, "Failed to update state", http.StatusInternalServerError)
		return
	}

	SendJSON(w, http.StatusOK, map[string]interface{}{"status": "success", "isArmed": req.IsArmed})
}

func (h *ConfigHandler) HandleVersion(w http.ResponseWriter, r *http.Request) {
	SendJSON(w, http.StatusOK, map[string]string{"version": h.service.GetVersion()})
}

// GetSystemUpdates returns update data from the updater service
func (h *ConfigHandler) GetSystemUpdates(w http.ResponseWriter, r *http.Request) {
	SendJSON(w, http.StatusOK, h.updater.GetState())
}

// CheckForUpdatesManual forces an on-demand update check for Hub, Wizard, and Sensors
func (h *ConfigHandler) CheckForUpdatesManual(w http.ResponseWriter, r *http.Request) {
	if h.updater != nil {
		if err := h.updater.CheckForUpdates(); err != nil {
			RespondError(w, err.Error(), http.StatusBadGateway)
			return
		}
		SendJSON(w, http.StatusOK, h.updater.GetState())
		return
	}
	RespondError(w, "Updater service unavailable", http.StatusServiceUnavailable)
}

// AcknowledgeWizardRelease records that the admin has dismissed or acknowledged a wizard release version
func (h *ConfigHandler) AcknowledgeWizardRelease(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Version string `json:"version"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		RespondError(w, "Invalid payload", http.StatusBadRequest)
		return
	}

	if err := h.service.AcknowledgeWizardRelease(req.Version); err != nil {
		RespondError(w, "Failed to acknowledge release", http.StatusInternalServerError)
		return
	}

	if h.updater != nil {
		h.updater.CheckForUpdates()
	}

	SendJSON(w, http.StatusOK, map[string]string{"status": "success"})
}
