package assets

import (
	"strings"
	"testing"
)

func TestValidate(t *testing.T) {
	got, err := Validate([]Asset{
		{Name: " pg-primary ", Address: "10.20.4.17", Criticality: "Critical", Tags: []string{" pci ", ""}},
		{Name: "core-vlan", Address: "10.20.0.0/16"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got[0].Name != "pg-primary" || got[0].Criticality != "critical" || len(got[0].Tags) != 1 || got[0].Tags[0] != "pci" {
		t.Errorf("first = %+v", got[0])
	}
	if got[1].Criticality != "medium" || got[1].Tags == nil {
		t.Errorf("defaults = %+v", got[1])
	}
	for name, list := range map[string][]Asset{
		"no name":   {{Address: "10.0.0.1"}},
		"bad ip":    {{Name: "a", Address: "10.0.0.300"}},
		"bad cidr":  {{Name: "a", Address: "10.0.0.0/33"}},
		"bad crit":  {{Name: "a", Address: "10.0.0.1", Criticality: "urgent"}},
		"duplicate": {{Name: "a", Address: "10.0.0.0/8"}, {Name: "b", Address: "10.1.2.3/8"}},
		"long name": {{Name: strings.Repeat("x", 300), Address: "10.0.0.1"}},
	} {
		if _, err := Validate(list); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestLookupMostSpecificWins(t *testing.T) {
	ix := NewIndex([]Asset{
		{Name: "corp", Address: "10.0.0.0/8", Criticality: "low"},
		{Name: "core-vlan", Address: "10.20.0.0/16", Criticality: "medium"},
		{Name: "pg-primary", Address: "10.20.4.17", Criticality: "critical"},
		{Name: "v6-lab", Address: "fd00:10::/32", Criticality: "high"},
	})
	for src, want := range map[string]string{
		"10.20.4.17":        "pg-primary",
		"10.20.4.17:51234":  "pg-primary",
		"::ffff:10.20.4.17": "pg-primary",
		"10.20.9.5":         "core-vlan",
		"10.99.0.1":         "corp",
		"fd00:10::5":        "v6-lab",
		"[fd00:10::5]:22":   "v6-lab",
		"192.168.1.1":       "",
		"Wizard Live Test":  "",
	} {
		r := ix.Lookup(src)
		got := ""
		if r != nil {
			got = r.Name
		}
		if got != want {
			t.Errorf("Lookup(%q) = %q, want %q", src, got, want)
		}
	}
}

func TestCache(t *testing.T) {
	var c Cache
	if c.Get(`[{"name":"a","address":"10.0.0.0/8","criticality":"high"}]`).Lookup("10.1.1.1") == nil {
		t.Fatal("cache did not index")
	}
	if c.Get("not json").Lookup("10.1.1.1") != nil {
		t.Fatal("undecodable inventory matched")
	}
	if c.Get("").Lookup("10.1.1.1") != nil {
		t.Fatal("empty inventory matched")
	}
}
