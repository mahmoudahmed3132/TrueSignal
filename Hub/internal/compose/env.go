package compose

import "github.com/truesignal/hub/internal/models"

var forbiddenUserVars = map[string]bool{
	"TS_HUB_ENDPOINT": true,
	"TS_HUB_KEY":      true,
	"TS_SENSOR_ID":    true,
	"TS_CONFIG_REV":   true,
	"TS_TEST_MODE":    true,
	// Set by the Hub: the node's capture key and the planted honeytoken.
	"TS_CAPTURE_HASH_KEY": true,
	"TS_HONEYTOKEN":       true,
	// Set by the Hub: the Token Receivers' beacon verification key.
	"TS_BEACON_KEY": true,
}

// BuildEnv securely merges manifest defaults, user overrides, and reserved system variables.
// User values are accepted only for variables the manifest declares, and
// never for reserved system keys. An undeclared name is dropped: otherwise
// a dashboard session could set e.g. HTTPS_PROXY or SSL_CERT_FILE and route
// a sensor's Hub traffic, node key included, through a proxy of its choice.
func BuildEnv(manifest models.SensorManifest, userVars map[string]string, systemVars map[string]string) map[string]string {
	envMap := make(map[string]string)
	declared := make(map[string]bool, len(manifest.Deployment.EnvVars))

	// 1. Load manifest defaults
	for _, v := range manifest.Deployment.EnvVars {
		envMap[v.Name] = v.Default
		declared[v.Name] = true
	}

	// 2. Merge user overrides of declared, non-reserved variables
	for k, v := range userVars {
		if forbiddenUserVars[k] || !declared[k] {
			continue
		}
		envMap[k] = v
	}

	// 3. Unconditionally inject system-reserved variables
	for k, v := range systemVars {
		envMap[k] = v
	}

	return envMap
}
