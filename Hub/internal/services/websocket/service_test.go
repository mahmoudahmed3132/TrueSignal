package websocket

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSameOrigin(t *testing.T) {
	policy := SameOrigin(func() []string { return []string{"hub.example.com"} }, func(*http.Request) bool { return true })
	cases := []struct {
		origin, host, fwd string
		want              bool
	}{
		{"", "hub:8080", "", true},
		{"https://hub:8080", "hub:8080", "", true},
		{"https://hub.example.com", "10.0.0.5:8080", "", true},
		{"https://proxy.example.com", "backend:8080", "proxy.example.com", true},
		{"https://evil.example", "hub:8080", "", false},
	}
	for _, c := range cases {
		r := httptest.NewRequest("GET", "/api/v2/ws", nil)
		r.Host = c.host
		if c.origin != "" {
			r.Header.Set("Origin", c.origin)
		}
		if c.fwd != "" {
			r.Header.Set("X-Forwarded-Host", c.fwd)
		}
		if got := policy(r); got != c.want {
			t.Errorf("origin=%q host=%q fwd=%q: got %v want %v", c.origin, c.host, c.fwd, got, c.want)
		}
	}
}
