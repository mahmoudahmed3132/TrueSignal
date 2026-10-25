package store

import (
	"path/filepath"
	"testing"
)

func TestRegistryURLDefaultAndLegacyMove(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "test_config.db")

	st, err := NewStore(dbPath)
	if err != nil {
		t.Fatalf("NewStore failed: %v", err)
	}
	if got, _ := st.GetConfigValue("registry_url"); got != DefaultRegistryURL {
		t.Fatalf("fresh registry_url = %q, want %q", got, DefaultRegistryURL)
	}

	// A Hub created before the source repository went private still holds
	// the old default: the next boot moves it.
	if err := st.UpdateConfigValue("registry_url", legacyRegistryURL); err != nil {
		t.Fatal(err)
	}
	if err := InitializeDefaultConfig(st.DB); err != nil {
		t.Fatal(err)
	}
	if got, _ := st.GetConfigValue("registry_url"); got != DefaultRegistryURL {
		t.Fatalf("legacy registry_url = %q after boot, want %q", got, DefaultRegistryURL)
	}

	// A custom registry is the operator's choice and is kept.
	const custom = "https://registry.example.internal/truesignal"
	if err := st.UpdateConfigValue("registry_url", custom); err != nil {
		t.Fatal(err)
	}
	if err := InitializeDefaultConfig(st.DB); err != nil {
		t.Fatal(err)
	}
	if got, _ := st.GetConfigValue("registry_url"); got != custom {
		t.Fatalf("custom registry_url = %q after boot, want %q", got, custom)
	}
	st.DB.Close()
}
