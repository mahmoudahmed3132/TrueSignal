package compose

import (
	"testing"

	"github.com/truesignal/hub/internal/models"
)

func TestBuildEnvAcceptsOnlyDeclaredNonReserved(t *testing.T) {
	var m models.SensorManifest
	m.Deployment.EnvVars = []models.ConfigVar{{Name: "TS_SERVICES", Default: "ssh:2222"}, {Name: "TS_HUB_KEY"}}
	env := BuildEnv(m, map[string]string{
		"TS_SERVICES": "ssh:22",
		"TS_HUB_KEY":  "forged",      // reserved
		"HTTPS_PROXY": "http://evil", // undeclared
		"LD_PRELOAD":  "/tmp/x.so",   // undeclared
		"TS_EXTRA":    "x",           // undeclared, even with the TS_ prefix
	}, map[string]string{"TS_HUB_KEY": "real"})
	if env["TS_SERVICES"] != "ssh:22" || env["TS_HUB_KEY"] != "real" {
		t.Fatalf("env = %v", env)
	}
	for _, k := range []string{"HTTPS_PROXY", "LD_PRELOAD", "TS_EXTRA"} {
		if _, ok := env[k]; ok {
			t.Errorf("undeclared %s passed through", k)
		}
	}
}
