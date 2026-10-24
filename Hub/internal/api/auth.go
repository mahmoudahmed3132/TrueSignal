package api

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/truesignal/hub/internal/services/auth"
	"github.com/truesignal/hub/internal/services/config"
)

const AuthCookieName = "ts_auth"

type AuthHandler struct {
	service *auth.Service
	Cfg     *config.Config
}

func NewAuthHandler(svc *auth.Service, cfg *config.Config) *AuthHandler {
	return &AuthHandler{
		service: svc,
		Cfg:     cfg,
	}
}

func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	ip := GetRealIP(r, h.Cfg.TrustsProxyHeaders(r))

	var req struct {
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		RespondError(w, "Invalid request", http.StatusBadRequest)
		return
	}

	token, err := h.service.Login(req.Password, ip)
	if err != nil {
		if err.Error() == "too_many_requests" {
			RespondError(w, "Too many failed attempts. Try again later.", http.StatusTooManyRequests)
			return
		}
		RespondError(w, "Invalid Password", http.StatusUnauthorized)
		return
	}

	ttl := h.service.SessionTTL()
	http.SetCookie(w, &http.Cookie{
		Name:     AuthCookieName,
		Value:    token,
		MaxAge:   int(ttl.Seconds()),
		Expires:  time.Now().Add(ttl),
		HttpOnly: true,
		Secure:   !h.Cfg.IsDevelopment(),
		SameSite: http.SameSiteStrictMode,
		Path:     "/",
	})

	SendJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie(AuthCookieName); err == nil {
		h.service.DeleteSession(cookie.Value)
	}

	clearAuthCookie(w, h.Cfg)

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// clearAuthCookie expires the session cookie with the same attributes it was
// issued with, so browsers reliably replace it.
func clearAuthCookie(w http.ResponseWriter, cfg *config.Config) {
	http.SetCookie(w, &http.Cookie{
		Name:     AuthCookieName,
		Value:    "",
		MaxAge:   -1,
		Expires:  time.Unix(0, 0),
		HttpOnly: true,
		Secure:   cfg != nil && !cfg.IsDevelopment(),
		SameSite: http.SameSiteStrictMode,
		Path:     "/",
	})
}
