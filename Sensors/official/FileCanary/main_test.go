package main

import (
	"strings"
	"testing"
	"time"
)

func TestLureContentByName(t *testing.T) {
	cases := map[string]string{
		".env.backup":        "DB_PASSWORD=",
		".backup-config.php": "define('DB_PASSWORD'",
		"dump.sql.bak":       "MySQL dump",
		"vpn_keys.txt":       "PrivateKey =",
		".pgpass.old":        "localhost:5432",
		"random.dat":         "token=",
	}
	for name, want := range cases {
		if got := string(lureContent(name, honeytoken{})); !strings.Contains(got, want) {
			t.Errorf("%s: expected %q in content, got %q", name, want, got)
		}
	}
	if string(lureContent(".env", honeytoken{})) == string(lureContent(".env", honeytoken{})) {
		t.Error("secrets must be random per lure")
	}
}

func TestLuresEmbedHoneytoken(t *testing.T) {
	tok, ok := parseHoneytoken("svc_backup7f3a:Qx7pLm2Rv9TzKw!")
	if !ok {
		t.Fatal("valid TS_HONEYTOKEN rejected")
	}
	for _, name := range []string{".env.backup", ".backup-config.php", "dump.sql.bak", "vpn_keys.txt", ".pgpass.old", "random.dat"} {
		got := string(lureContent(name, tok))
		if !strings.Contains(got, "svc_backup7f3a") || !strings.Contains(got, "Qx7pLm2Rv9TzKw!") {
			t.Errorf("%s does not carry the honeytoken:\n%s", name, got)
		}
	}
	for _, bad := range []string{"", "nouser", ":pw", "user:"} {
		if _, ok := parseHoneytoken(bad); ok {
			t.Errorf("parseHoneytoken(%q) accepted", bad)
		}
	}
}

func TestDeduper(t *testing.T) {
	d := newDeduper(10 * time.Second)
	t0 := time.Unix(0, 0)
	if !d.allow("f|open", t0) || d.allow("f|open", t0.Add(time.Second)) {
		t.Fatal("burst within window must collapse")
	}
	if !d.allow("f|read", t0.Add(time.Second)) {
		t.Fatal("different action is a different key")
	}
	if !d.allow("f|open", t0.Add(11*time.Second)) {
		t.Fatal("window expiry must allow again")
	}
}
