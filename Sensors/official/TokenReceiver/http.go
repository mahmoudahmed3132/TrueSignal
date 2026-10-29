package main

import (
	"net"
	"net/http"
	"path"
	"strings"
	"time"

	sdk "github.com/truesignal/sdk-go"
	"github.com/truesignal/sdk-go/decoy"
)

// The HTTP side answers every request with the same 1x1 transparent GIF and
// no-cache headers, whether or not it carried a token, so a probe learns
// nothing and a re-opened document fires again. A token is looked for in the
// path segments (extension stripped) and in the Host labels below the zone.

var pixel = []byte{
	0x47, 0x49, 0x46, 0x38, 0x39, 0x61, 0x01, 0x00, 0x01, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00,
	0xff, 0xff, 0xff, 0x21, 0xf9, 0x04, 0x01, 0x00, 0x00, 0x00, 0x00, 0x2c, 0x00, 0x00, 0x00, 0x00,
	0x01, 0x00, 0x01, 0x00, 0x00, 0x02, 0x02, 0x44, 0x01, 0x00, 0x3b,
}

func (r *receiver) httpServer() *http.Server {
	return &http.Server{
		Handler:           http.HandlerFunc(r.serveHTTP),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    8 << 10,
	}
}

func (r *receiver) serveHTTP(w http.ResponseWriter, req *http.Request) {
	peer := decoy.RemoteIP(addr(req.RemoteAddr))
	src := r.clientIP(peer, req.Header.Get("X-Forwarded-For"))

	var candidates []string
	for _, seg := range strings.Split(req.URL.Path, "/") {
		if i := strings.IndexByte(seg, '.'); i >= 0 {
			seg = seg[:i]
		}
		candidates = append(candidates, seg)
	}
	host := req.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	if below, ok := r.zone.inZone(host); ok {
		candidates = append(candidates, below...)
	}
	if tok := r.verify.find(candidates...); tok != "" {
		d := sdk.EventDetails{
			{Key: "method", Value: decoy.Sanitize(req.Method, 16)},
			{Key: "host", Value: decoy.Sanitize(req.Host, 256)},
			{Key: "path", Value: decoy.Sanitize(path.Clean("/"+req.URL.Path), 256)},
			{Key: "user_agent", Value: decoy.Sanitize(req.UserAgent(), 256)},
		}
		if ref := req.Referer(); ref != "" {
			d = append(d, sdk.EventDetail{Key: "referer", Value: decoy.Sanitize(ref, 256)})
		}
		if src != peer {
			d = append(d, sdk.EventDetail{Key: "proxy", Value: peer})
		}
		r.report(tok, "http", src, d)
	}

	h := w.Header()
	h.Set("Content-Type", "image/gif")
	h.Set("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
	h.Set("Pragma", "no-cache")
	h.Set("Expires", "0")
	w.WriteHeader(http.StatusOK)
	if req.Method != http.MethodHead {
		w.Write(pixel)
	}
}

// clientIP believes X-Forwarded-For only from TS_TRUSTED_PROXIES (a TLS
// front end such as F5), and then takes the address the proxy appended.
func (r *receiver) clientIP(peer, xff string) string {
	if xff == "" || !r.trustedProxy(peer) {
		return peer
	}
	parts := strings.Split(xff, ",")
	last := strings.TrimSpace(parts[len(parts)-1])
	if net.ParseIP(last) == nil {
		return peer
	}
	return last
}

func (r *receiver) trustedProxy(ip string) bool {
	p := net.ParseIP(ip)
	if p == nil {
		return false
	}
	for _, n := range r.proxies {
		if n.Contains(p) {
			return true
		}
	}
	return false
}

type strAddr string

func (a strAddr) Network() string { return "tcp" }
func (a strAddr) String() string  { return string(a) }

func addr(s string) net.Addr { return strAddr(s) }
