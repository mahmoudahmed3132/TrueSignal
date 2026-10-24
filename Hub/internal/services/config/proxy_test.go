package config

import (
	"net/http/httptest"
	"testing"
)

func TestTrustsProxyHeaders(t *testing.T) {

	proxies, err := ParseTrustedProxies(" 10.0.0.5, 192.168.10.0/24 ,::ffff:172.16.0.9, fd00::/8")
	if err != nil || len(proxies) != 4 {
		t.Fatalf("parse = %v, %v", proxies, err)
	}
	cases := []struct {
		cfg  *Config
		peer string
		want bool
	}{
		{nil, "10.0.0.5:1", false},
		{&Config{TrustProxy: false, TrustedProxies: proxies}, "10.0.0.5:1", false},
		{&Config{TrustProxy: true}, "203.0.113.9:1", true}, // legacy: any peer
		{&Config{TrustProxy: true, TrustedProxies: proxies}, "10.0.0.5:443", true},
		{&Config{TrustProxy: true, TrustedProxies: proxies}, "10.0.0.6:443", false},
		{&Config{TrustProxy: true, TrustedProxies: proxies}, "192.168.10.77:1", true},
		{&Config{TrustProxy: true, TrustedProxies: proxies}, "172.16.0.9:1", true},        // IPv4-mapped entry
		{&Config{TrustProxy: true, TrustedProxies: proxies}, "[::ffff:10.0.0.5]:1", true}, // IPv4-mapped peer
		{&Config{TrustProxy: true, TrustedProxies: proxies}, "[fd12::1]:1", true},
		{&Config{TrustProxy: true, TrustedProxies: proxies}, "garbage", false},
	}
	for _, c := range cases {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = c.peer
		if got := c.cfg.TrustsProxyHeaders(r); got != c.want {
			t.Errorf("peer %s cfg %+v: got %v, want %v", c.peer, c.cfg, got, c.want)
		}
	}
}

func TestParseTrustedProxiesRejectsTypos(t *testing.T) {
	for _, bad := range []string{"10.0.0.300", "10.0.0.0/33", "proxy.local", "10.0.0.1/"} {
		if _, err := ParseTrustedProxies(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	if p, err := ParseTrustedProxies(""); err != nil || len(p) != 0 {
		t.Errorf("empty = %v, %v", p, err)
	}
}
