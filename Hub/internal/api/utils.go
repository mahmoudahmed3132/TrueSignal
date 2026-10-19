package api

import (
	"encoding/json"
	"log"
	"net"
	"net/http"
	"strings"
)

// --- Helpers ---

func RespondError(w http.ResponseWriter, message string, code int) {
	SendJSON(w, code, map[string]string{"error": message})
}

func SendJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		log.Printf("[ERROR] SendJSON encode error: %v\n", err)
	}
}

// GetRealIP returns the client IP. Behind a trusted reverse proxy it prefers
// X-Real-IP (set by the proxy), then the right-most X-Forwarded-For entry: the
// left-most entries are client-supplied and trivially spoofed.
func GetRealIP(r *http.Request, trustProxy bool) string {
	if trustProxy {
		if ip := strings.TrimSpace(r.Header.Get("X-Real-IP")); ip != "" && net.ParseIP(ip) != nil {
			return ip
		}
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			parts := strings.Split(xff, ",")
			if ip := strings.TrimSpace(parts[len(parts)-1]); net.ParseIP(ip) != nil {
				return ip
			}
		}
	}
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return ip
}
