package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func fakeHub(t *testing.T, enrollOnly bool) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req map[string]string
		json.NewDecoder(r.Body).Decode(&req)
		w.Header().Set("Content-Type", "application/json")
		switch {
		case req["password"] != "pw":
			w.WriteHeader(401)
			w.Write([]byte(`{"error":"Invalid Password"}`))
		case enrollOnly:
			http.SetCookie(w, &http.Cookie{Name: "ts_auth", Value: "restricted"})
			w.Write([]byte(`{"status":"mfa_enrollment_required"}`))
		case req["code"] == "":
			w.WriteHeader(401)
			w.Write([]byte(`{"error":"mfa_required"}`))
		case req["code"] != "123456":
			w.WriteHeader(401)
			w.Write([]byte(`{"error":"invalid_code"}`))
		default:
			http.SetCookie(w, &http.Cookie{Name: "ts_auth", Value: "sess"})
			w.Write([]byte(`{"status":"ok"}`))
		}
	}))
}

func TestDashboardLoginMFA(t *testing.T) {
	srv := fakeHub(t, false)
	defer srv.Close()
	c := NewClient(srv.URL)
	ctx := context.Background()

	if _, err := c.AuthenticateDashboard(ctx, "pw"); !errors.Is(err, ErrMFARequired) {
		t.Fatalf("no code: %v", err)
	}
	if _, err := c.AuthenticateDashboardCode(ctx, "pw", "000000"); err == nil || !strings.Contains(err.Error(), "invalid MFA code") {
		t.Fatalf("bad code: %v", err)
	}
	if cookie, err := c.AuthenticateDashboardCode(ctx, "pw", "123456"); err != nil || cookie != "sess" {
		t.Fatalf("good code: %q %v", cookie, err)
	}
	if _, err := c.AuthenticateDashboard(ctx, "nope"); err == nil || errors.Is(err, ErrMFARequired) {
		t.Fatalf("bad password: %v", err)
	}
}

func TestDashboardLoginEnrollOnlySessionRejected(t *testing.T) {
	srv := fakeHub(t, true)
	defer srv.Close()
	// A restricted session is useless to the wizard: fail with guidance.
	if _, err := NewClient(srv.URL).AuthenticateDashboard(context.Background(), "pw"); err == nil || !strings.Contains(err.Error(), "enroll") {
		t.Fatalf("enroll-only: %v", err)
	}
}
