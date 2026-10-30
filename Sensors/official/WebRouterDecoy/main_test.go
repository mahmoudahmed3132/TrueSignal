package main

import (
	"strings"
	"testing"
	"time"
)

func TestPasswordDetailsModes(t *testing.T) {
	key := passwordHashKey("", "ts_key_node")
	h := passwordDetails("hunter2", "hash", key)
	if h[0].Key != "attempted_password_hmac" || len(h[0].Value.(string)) != 64 || h[1].Value != 7 || h[2].Key != "hmac_key_id" {
		t.Errorf("hash mode: %+v", h)
	}
	// Unkeyed SHA-256("hunter2"): must not be what we emit.
	if h[0].Value == "f52fbd32b2b3b86ff88ef6c490628285f482af15ddcb29541f94bcf526a3f6c7" {
		t.Fatal("hash mode must be keyed, not a bare SHA-256")
	}
	for _, d := range h {
		if d.Value == "hunter2" {
			t.Fatal("hash mode must never include the cleartext password")
		}
	}
	if again := passwordDetails("hunter2", "hash", key); again[0].Value != h[0].Value {
		t.Error("same key and password must give the same HMAC (correlation)")
	}
	if other := passwordDetails("hunter2", "hash", passwordHashKey("", "ts_key_other")); other[0].Value == h[0].Value {
		t.Error("different node keys must give different HMACs")
	}
	shared := passwordHashKey("fleet-secret", "ts_key_node")
	if a, b := passwordDetails("x", "hash", shared), passwordDetails("x", "hash", passwordHashKey("fleet-secret", "ts_key_other")); a[0].Value != b[0].Value {
		t.Error("TS_CAPTURE_HASH_KEY must correlate across nodes")
	}
	if p := passwordDetails("hunter2", "plain", key); p[0].Value != "hunter2" {
		t.Errorf("plain mode: %+v", p)
	}
	if n := passwordDetails("hunter2", "none", key); n[0].Key != "password_submitted" || n[0].Value != true {
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
	ok1, _ := p.allow("1.2.3.4", t0)
	ok2, _ := p.allow("1.2.3.4", t0.Add(time.Second))
	p.allow("1.2.3.4", t0.Add(2*time.Second))
	ok3, suppressed := p.allow("1.2.3.4", t0.Add(2*time.Minute))
	if !ok1 || ok2 || !ok3 || suppressed != 2 {
		t.Fatalf("window or suppressed count wrong: %v %v %v %d", ok1, ok2, ok3, suppressed)
	}
}
