package decoy

import (
	"strings"
	"testing"
	"time"
)

func TestParseServices(t *testing.T) {
	got, err := ParseServices(" mysql:3306, POSTGRES:5432 ", "mysql", "postgres")
	if err != nil || len(got) != 2 || got[1] != (Service{"postgres", 5432}) {
		t.Fatalf("got %v, %v", got, err)
	}
	for _, bad := range []string{"", "ssh:22", "mysql", "mysql:0", "mysql:70000", "mysql:3306,postgres:3306"} {
		if _, err := ParseServices(bad, "mysql", "postgres"); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestCaptureModes(t *testing.T) {
	h := NewCaptureWith("", "k", "node")
	d := h.Password("Winter2026!")
	if d[0].Key != "password_hmac" || d[1].Value != 11 || d[2].Key != "hmac_key_id" {
		t.Fatalf("hash = %+v", d)
	}
	for _, kv := range d {
		if s, ok := kv.Value.(string); ok && strings.Contains(s, "Winter") {
			t.Fatal("cleartext in hash mode")
		}
	}
	if p := NewCaptureWith("plain", "", "n").Password("x"); p[0].Key != "password" || p[0].Value != "x" {
		t.Fatalf("plain = %+v", p)
	}
	if n := NewCaptureWith("none", "", "n").Password("x"); n[0].Key != "password_submitted" {
		t.Fatalf("none = %+v", n)
	}
	// Same key, same HMAC; the key ID depends only on the key.
	if NewCaptureWith("hash", "k", "a").KeyID() != NewCaptureWith("hash", "k", "b").KeyID() {
		t.Fatal("key ID must depend on the capture key only")
	}
}

func TestSanitize(t *testing.T) {
	if got := Sanitize("ab\xffcd", 0); got != "ab?cd" {
		t.Fatalf("got %q", got)
	}
	if got := Sanitize("héllo", 2); got != "h" {
		t.Fatalf("truncation split a rune: %q", got)
	}
}

func TestLimiter(t *testing.T) {
	l := NewLimiter(2, time.Minute)
	t0 := time.Unix(0, 0)
	l.now = func() time.Time { return t0 }
	if ok, _ := l.Allow("a"); !ok {
		t.Fatal("first")
	}
	if ok, _ := l.Allow("a"); !ok {
		t.Fatal("second")
	}
	for i := 0; i < 5; i++ {
		if ok, _ := l.Allow("a"); ok {
			t.Fatal("over limit allowed")
		}
	}
	if ok, _ := l.Allow("b"); !ok {
		t.Fatal("other source limited")
	}
	l.now = func() time.Time { return t0.Add(61 * time.Second) }
	if ok, sup := l.Allow("a"); !ok || sup != 5 {
		t.Fatalf("new window: ok=%v suppressed=%d, want 5", ok, sup)
	}
}
