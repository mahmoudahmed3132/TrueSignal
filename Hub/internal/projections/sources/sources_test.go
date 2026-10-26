package sources

import (
	"testing"

	"github.com/truesignal/hub/internal/assets"
	"github.com/truesignal/hub/internal/services/sourcelist"
	"github.com/truesignal/hub/internal/store"
)

func TestClassify(t *testing.T) {
	for src, want := range map[string][2]bool{
		"10.1.2.3":         {true, true},
		"172.31.0.1":       {true, true},
		"172.32.0.1":       {true, false},
		"100.64.1.1":       {true, true},
		"8.8.8.8":          {true, false},
		"192.168.1.9:4431": {true, true},
		"fd00::1":          {true, true},
		"2001:db8::1":      {true, false},
		"::ffff:10.0.0.1":  {true, true},
		"Wizard Live Test": {false, false},
		"":                 {false, false},
	} {
		isIP, internal := Classify(src)
		if isIP != want[0] || internal != want[1] {
			t.Errorf("Classify(%q) = %v/%v, want %v/%v", src, isIP, internal, want[0], want[1])
		}
	}
}

func TestBuild(t *testing.T) {
	wl, _ := sourcelist.Parse("10.0.0.0/24")
	sc, _ := sourcelist.Parse("nessus-01")
	got := Build([]store.SourceActivity{
		{Source: "10.0.0.5", Events: 2, Decoys: 1},
		{Source: "nessus-01", Events: 9, Decoys: 4},
		{Source: "203.0.113.7", Events: 2, Decoys: 2},
		{Source: "198.51.100.20", Events: 1, Decoys: 1},
	}, wl, sc, assets.NewIndex([]assets.Asset{{Name: "edge-gw", Address: "198.51.100.0/24", Criticality: "high"}}))
	if got[0].Source != "nessus-01" || !got[0].KnownScanner || got[0].IsIP {
		t.Errorf("first = %+v", got[0])
	}
	if got[1].Source != "10.0.0.5" || !got[1].Whitelisted || !got[1].Internal {
		t.Errorf("second = %+v", got[1])
	}
	if got[2].Source != "203.0.113.7" || got[2].Internal || got[2].Whitelisted || got[2].Asset != nil {
		t.Errorf("third = %+v", got[2])
	}
	// A public address on the inventory is internal and carries its asset.
	if got[3].Source != "198.51.100.20" || !got[3].Internal || got[3].Asset == nil || got[3].Asset.Name != "edge-gw" {
		t.Errorf("fourth = %+v", got[3])
	}
}
