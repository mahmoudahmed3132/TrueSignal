package sourcelist

import (
	"strings"
	"testing"
)

func TestMatch(t *testing.T) {
	l, err := Parse("10.20.0.0/16, 192.168.1.5\n# scanners\nfd00::/8\n\nWizard Live Test,  ::ffff:172.16.0.9 ")
	if err != nil {
		t.Fatal(err)
	}
	for source, want := range map[string]bool{
		"10.20.4.17":       true,
		"10.21.0.1":        false,
		"192.168.1.5":      true,
		"192.168.1.6":      false,
		"192.168.1.5:4431": true,
		"fd12::1":          true,
		"[fd12::1]:22":     true,
		"fe80::1":          false,
		"172.16.0.9":       true,
		"::ffff:10.20.0.1": true,
		"Wizard Live Test": true,
		"wizard live test": false,
		"Unknown":          false,
		"":                 false,
	} {
		if got := l.Match(source); got != want {
			t.Errorf("Match(%q) = %v, want %v", source, got, want)
		}
	}
	var nilList *List
	if nilList.Match("10.20.0.1") {
		t.Error("nil list matched")
	}
}

func TestParseErrors(t *testing.T) {
	for _, raw := range []string{"10.0.0.0/33", "not/a-cidr", strings.Repeat("a", MaxEntryLen+1)} {
		if _, err := Parse(raw); err == nil {
			t.Errorf("Parse(%q) accepted an invalid entry", raw)
		}
	}
	if _, err := Parse(strings.Repeat("10.0.0.1,", MaxEntries+1)); err == nil {
		t.Error("Parse accepted more than MaxEntries")
	}
	if _, err := Parse(""); err != nil {
		t.Errorf("empty list: %v", err)
	}
}

func TestNormalize(t *testing.T) {
	got := Normalize("10.0.0.1\n10.0.0.0/8,10.0.0.1\r\n# comment\n scanner-a ")
	if want := "10.0.0.1, 10.0.0.0/8, scanner-a"; got != want {
		t.Errorf("Normalize = %q, want %q", got, want)
	}
}

func TestCache(t *testing.T) {
	var c Cache
	if !c.Get("10.0.0.0/8").Match("10.1.2.3") {
		t.Fatal("cache did not parse")
	}
	if c.Get("192.168.0.0/16").Match("10.1.2.3") {
		t.Fatal("cache did not re-parse a changed list")
	}
	// A stored entry that is not a valid CIDR stays a plain name (lists
	// saved before CIDR support), and the rest of the list still works.
	l := c.Get("legacy/name, 10.0.0.0/8")
	if !l.Match("legacy/name") || !l.Match("10.9.9.9") {
		t.Fatal("lenient parse lost entries")
	}
}
