package main

import (
	"strings"
	"testing"
	"time"
)

func TestPasswordDetailsModes(t *testing.T) {
	h := passwordDetails("hunter2", "hash")
	if h[0].Key != "attempted_password_sha256" || h[0].Value != "f52fbd32b2b3b86ff88ef6c490628285f482af15ddcb29541f94bcf526a3f6c7" || h[1].Value != 7 {
		t.Errorf("hash mode: %+v", h)
	}
	for _, d := range h {
		if d.Value == "hunter2" {
			t.Fatal("hash mode must never include the cleartext password")
		}
	}
	if p := passwordDetails("hunter2", "plain"); p[0].Value != "hunter2" {
		t.Errorf("plain mode: %+v", p)
	}
	if n := passwordDetails("hunter2", "none"); n[0].Key != "password_submitted" || n[0].Value != true {
		t.Errorf("none mode: %+v", n)
	}
}

func TestBrandProfileConsistency(t *testing.T) {
	if m, _ := brandProfile("Netgear"); m != "R7000" {
		t.Errorf("netgear model %q", m)
	}
	if m, _ := brandProfile("Cisco"); m != "RV340" {
		t.Errorf("cisco model %q", m)
	}
	if m, _ := brandProfile("<script>"); strings.Contains(m, "<") {
		t.Errorf("unknown brand must map to a neutral model")
	}
}

func TestProbeLimiter(t *testing.T) {
	p := newProbeLimiter(time.Minute)
	t0 := time.Unix(0, 0)
	if !p.allow("1.2.3.4", t0) || p.allow("1.2.3.4", t0.Add(time.Second)) || !p.allow("1.2.3.4", t0.Add(2*time.Minute)) {
		t.Fatal("limiter window not respected")
	}
}
