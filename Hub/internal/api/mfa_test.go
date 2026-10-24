package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/truesignal/hub/internal/services/auth"
	"github.com/truesignal/hub/internal/services/config"
)

type memStore struct{ kv map[string]string }

func (m *memStore) GetConfigValue(k string) (string, error) {
	if v, ok := m.kv[k]; ok {
		return v, nil
	}
	return "", errors.New("not found")
}
func (m *memStore) UpdateConfigValue(k, v string) error { m.kv[k] = v; return nil }
func (m *memStore) GetNodeByKey(string) (string, error) { return "", errors.New("no") }

func post(h http.HandlerFunc, path, body string, cookie *http.Cookie) *httptest.ResponseRecorder {
	req := httptest.NewRequest("POST", path, strings.NewReader(body))
	if cookie != nil {
		req.AddCookie(cookie)
	}
	rec := httptest.NewRecorder()
	h(rec, req)
	return rec
}

func TestLoginRequireMFAGivesEnrollOnlySession(t *testing.T) {
	svc := auth.NewService(&memStore{kv: map[string]string{}}, "pw-correct-horse", auth.SessionPolicy{RequireMFA: true})
	cfg := &config.Config{Env: "production"}
	login := NewAuthHandler(svc, cfg)
	mfa := NewMFAHandler(svc, cfg)

	rec := post(login.Login, "/login", `{"password":"pw-correct-horse"}`, nil)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"status":"mfa_enrollment_required"`) {
		t.Fatalf("login = %d %s", rec.Code, rec.Body)
	}
	cookie := rec.Result().Cookies()[0]

	// The gate: only the enrollment endpoints are reachable.
	protected := UIAuthMiddleware(svc)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	for path, want := range map[string]int{
		"GET /api/v2/auth/mfa":          http.StatusNoContent,
		"POST /api/v2/auth/mfa/setup":   http.StatusNoContent,
		"POST /api/v2/auth/mfa/enable":  http.StatusNoContent,
		"GET /api/v2/nodes":             http.StatusForbidden,
		"POST /api/v2/auth/mfa/disable": http.StatusForbidden,
		"PATCH /api/v2/config":          http.StatusForbidden,
	} {
		m, p, _ := strings.Cut(path, " ")
		req := httptest.NewRequest(m, p, nil)
		req.AddCookie(cookie)
		rec := httptest.NewRecorder()
		protected.ServeHTTP(rec, req)
		if rec.Code != want {
			t.Errorf("%s = %d, want %d (%s)", path, rec.Code, want, rec.Body)
		}
	}

	// The dual-auth routes (sensor manifests) honour the gate too, while a
	// node key on the same routes is unaffected.
	dual := DualAuthMiddleware(svc, svc, NewRateLimiter())(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	req := httptest.NewRequest("GET", "/api/v2/manifests", nil)
	req.AddCookie(cookie)
	rec = httptest.NewRecorder()
	dual.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("dual-auth manifests with enroll-only session = %d, want 403", rec.Code)
	}

	// Setup returns the secret, the otpauth URI and a QR PNG, uncached.
	rec = post(mfa.Setup, "/api/v2/auth/mfa/setup", `{"password":"pw-correct-horse"}`, cookie)
	var setup map[string]string
	json.Unmarshal(rec.Body.Bytes(), &setup)
	if rec.Code != 200 || setup["secret"] == "" || !strings.HasPrefix(setup["uri"], "otpauth://totp/") ||
		!strings.HasPrefix(setup["qr"], "data:image/png;base64,") || rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("setup = %d %v %v", rec.Code, setup, rec.Header())
	}
	if rec := post(mfa.Setup, "/api/v2/auth/mfa/setup", `{"password":"nope"}`, cookie); rec.Code != http.StatusUnauthorized {
		t.Fatalf("setup with wrong password = %d", rec.Code)
	}
}

func TestLoginMFAResponses(t *testing.T) {
	st := &memStore{kv: map[string]string{}}
	svc := auth.NewService(st, "pw-correct-horse")
	login := NewAuthHandler(svc, &config.Config{Env: "production"})
	// Enroll through the service, then log in through the handler.
	tok, _ := svc.CreateSession()
	e, err := svc.BeginEnrollment(tok, "pw-correct-horse", "1.1.1.1")
	if err != nil {
		t.Fatal(err)
	}
	st.kv["mfa_secret"] = e.Secret // enabled without confirming, for the handler test

	if rec := post(login.Login, "/login", `{"password":"pw-correct-horse"}`, nil); rec.Code != 401 || !bytes.Contains(rec.Body.Bytes(), []byte(`"error":"mfa_required"`)) || len(rec.Result().Cookies()) != 0 {
		t.Fatalf("no code = %d %s", rec.Code, rec.Body)
	}
	if rec := post(login.Login, "/login", `{"password":"pw-correct-horse","code":"000000"}`, nil); rec.Code != 401 || !bytes.Contains(rec.Body.Bytes(), []byte(`"error":"invalid_code"`)) {
		t.Fatalf("bad code = %d %s", rec.Code, rec.Body)
	}
	if rec := post(login.Login, "/login", `{"password":"wrong","code":"000000"}`, nil); rec.Code != 401 || !bytes.Contains(rec.Body.Bytes(), []byte(`Invalid Password`)) {
		t.Fatalf("bad password = %d %s", rec.Code, rec.Body)
	}
}
