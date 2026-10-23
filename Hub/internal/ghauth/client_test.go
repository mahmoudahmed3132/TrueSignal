package ghauth

import (
	"net/http"
	"testing"
	"time"
)

type recorder struct{ got map[string]string }

func (r *recorder) RoundTrip(req *http.Request) (*http.Response, error) {
	r.got[req.URL.String()] = req.Header.Get("Authorization")
	return &http.Response{StatusCode: http.StatusOK, Body: http.NoBody, Request: req}, nil
}

func TestTokenOnlySentToGitHubHTTPS(t *testing.T) {
	rec := &recorder{got: map[string]string{}}
	c := NewClient("secret", time.Second)
	c.Transport.(*transport).base = rec

	cases := map[string]string{
		"https://raw.githubusercontent.com/o/r/registry-pages/index.json": "token secret",
		"https://api.github.com/repos/o/r/releases":                       "token secret",
		"http://raw.githubusercontent.com/o/r/index.json":                 "",
		"https://raw.githubusercontent.com:8443/o/r/index.json":           "",
		"https://evil.example/index.json":                                 "",
		"https://raw.githubusercontent.com.evil.example/index.json":       "",
	}
	for u := range cases {
		req, _ := http.NewRequest(http.MethodGet, u, nil)
		if _, err := c.Do(req); err != nil {
			t.Fatalf("%s: %v", u, err)
		}
	}
	for u, want := range cases {
		if got := rec.got[u]; got != want {
			t.Errorf("%s: Authorization=%q, want %q", u, got, want)
		}
	}
}

func TestEmptyTokenSendsNothing(t *testing.T) {
	rec := &recorder{got: map[string]string{}}
	c := NewClient("", time.Second)
	c.Transport.(*transport).base = rec
	u := "https://api.github.com/repos/o/r/releases"
	req, _ := http.NewRequest(http.MethodGet, u, nil)
	if _, err := c.Do(req); err != nil {
		t.Fatal(err)
	}
	if rec.got[u] != "" {
		t.Fatalf("unexpected Authorization %q", rec.got[u])
	}
}
