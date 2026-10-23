// Package ghauth builds HTTP clients that authenticate to GitHub with the
// Hub's read-only token (TS_GITHUB_TOKEN) so the sensor registry and release
// checks work while the repository is private.
package ghauth

import (
	"net/http"
	"time"
)

// tokenHosts are the only hosts that ever receive the token. registry_url is
// editable from the dashboard, so the token must never follow it to an
// arbitrary host.
var tokenHosts = map[string]bool{
	"raw.githubusercontent.com": true,
	"api.github.com":            true,
}

type transport struct {
	token string
	base  http.RoundTripper
}

func (t *transport) RoundTrip(req *http.Request) (*http.Response, error) {
	if t.token == "" || req.URL.Scheme != "https" || !tokenHosts[req.URL.Hostname()] || req.URL.Port() != "" {
		return t.base.RoundTrip(req)
	}
	authed := req.Clone(req.Context())
	authed.Header.Set("Authorization", "token "+t.token)
	return t.base.RoundTrip(authed)
}

// NewClient returns a client that adds the token to GitHub requests only.
// An empty token yields a plain client.
func NewClient(token string, timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout:   timeout,
		Transport: &transport{token: token, base: http.DefaultTransport},
	}
}
