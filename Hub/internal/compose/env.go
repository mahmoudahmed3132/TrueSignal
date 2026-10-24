package compose

import "github.com/truesignal/hub/internal/models"

var forbiddenUserVars = map[string]bool{
	"TS_HUB_ENDPOINT": true,
	"TS_HUB_KEY":      true,
	"TS_SENSOR_ID":    true,
	"TS_CONFIG_REV":   true,
	"TS_TEST_MODE":    true,
	// Set by the Hub: the fleet capture key and the planted honeytoken.
	"TS_CAPTURE_HASH_KEY": true,
	"TS_HONEYTOKEN":       true,
}

// BuildEnv securely merges manifest defaults, user overrides, and reserved system variables.
// It explicitly drops any user-provided variables that attempt to override reserved system keys.
func BuildEnv(manifest models.SensorManifest, userVars map[string]string, systemVars map[string]string) map[string]string {
	envMap := make(map[string]string)

	// 1. Load manifest defaults
	for _, v := range manifest.Deployment.EnvVars {
		envMap[v.Name] = v.Default
	}

	// 2. Safely merge user overrides (blocking forbidden keys)
	for k, v := range userVars {
		if forbiddenUserVars[k] {
			continue // Drop malicious/accidental overrides
		}
		envMap[k] = v
	}

	// 3. Unconditionally inject system-reserved variables
	for k, v := range systemVars {
		envMap[k] = v
	}

	return envMap
}
