package security

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/mod/semver"

	"github.com/truesignal/hub/internal/models"
)

// TestOfficialManifestsAreValid checks every source manifest under
// Sensors/official against the same strict decode and sandbox validation the
// Hub applies to published ones, so a manifest that the Hub would reject is
// caught before it is tagged.
func TestOfficialManifestsAreValid(t *testing.T) {
	paths, err := filepath.Glob("../../../../Sensors/official/*/*.json")
	if err != nil || len(paths) == 0 {
		t.Fatalf("no manifests found: %v", err)
	}
	hubMajor := semver.Major("v" + models.HubVersion)
	for _, p := range paths {
		t.Run(filepath.Base(filepath.Dir(p)), func(t *testing.T) {
			f, err := os.Open(p)
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			m, err := DecodeManifestStrict(f)
			if err != nil {
				t.Fatalf("%s: %v", p, err)
			}
			if err := ValidateManifest(m); err != nil {
				t.Fatalf("%s: %v", p, err)
			}
			if !strings.HasPrefix(m.ID, "ts-sensor-") {
				t.Errorf("id %q must start with ts-sensor-", m.ID)
			}
			if semver.Major("v"+m.Version) != hubMajor {
				t.Errorf("version %s: major must equal the Hub's (%s)", m.Version, hubMajor)
			}
		})
	}
}
