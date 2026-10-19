package compose

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/truesignal/hub/internal/compose/security"
	"github.com/truesignal/hub/internal/models"
)

// CoreEnvVars defines the ordered list of system-reserved environment variables.
var CoreEnvVars = []string{
	"TS_SENSOR_ID",
	"TS_HUB_ENDPOINT",
	"TS_HUB_KEY",
	"TS_CONFIG_REV",
	"TS_TEST_MODE",
	"TS_SEVERITY",
}

func buildImageString(repo, tag, digest string) string {
	img := repo
	if tag != "" {
		img += ":" + tag
	} else {
		img += ":latest"
	}
	if digest != "" {
		img += "@" + digest
	}
	return img
}

func BuildService(sensorID string, m models.SensorManifest, envMap map[string]string) (*ComposeFile, error) {
	var compose ComposeFile

	// -----------------------------------------------------------------
	// INIT CONTAINERS
	// -----------------------------------------------------------------
	// Sort InitContainers alphabetically by Name
	var initContainers []models.InitContainer
	initContainers = append(initContainers, m.Deployment.InitContainers...)
	sort.Slice(initContainers, func(i, j int) bool {
		return initContainers[i].Name < initContainers[j].Name
	})

	for _, ic := range initContainers {
		// Init containers run once, as provisioners. They get the same baseline
		// as sensors (read-only rootfs, all caps dropped, no-new-privileges)
		// and no network at all: provisioning never needs egress.
		initSvc := &ComposeService{
			Image:       buildImageString(ic.ImageRepository, ic.ImageTag, ic.ImageDigest),
			Command:     ic.Command,
			NetworkMode: "none",
			ReadOnly:    true,
			CapDrop:     []string{"ALL"},
			SecurityOpt: []string{"no-new-privileges:true"},
		}

		if ic.User != "" {
			initSvc.User = ic.User
		}

		initSvc.CapAdd = []string{}
		for _, cap := range ic.CapAdd {
			if security.AllowedCaps[cap] {
				initSvc.CapAdd = append(initSvc.CapAdd, cap)
			}
		}

		// Init Volumes
		var initVols []models.VolumeMount
		initVols = append(initVols, ic.VolumeMounts...)
		sort.Slice(initVols, func(i, j int) bool {
			return initVols[i].Target < initVols[j].Target
		})

		for _, vol := range initVols {
			if vol.Type == models.DynamicDirBind {
				// Handle dynamic dir bind
				filesStr := envMap[vol.SourceEnv]
				files := strings.Split(filesStr, ",")
				dirSet := make(map[string]bool)
				var dirs []string
				for _, f := range files {
					f = strings.TrimSpace(f)
					if f == "" {
						continue
					}
					if err := security.ValidateMountPath(f); err != nil {
						return nil, fmt.Errorf("dynamic volume expansion blocked for init container: %w", err)
					}
					dir := filepath.Dir(filepath.Clean(f))
					if !dirSet[dir] {
						dirSet[dir] = true
						dirs = append(dirs, dir)
					}
				}
				sort.Strings(dirs)
				for _, dir := range dirs {
					if err := security.ValidateMountPath(dir); err != nil {
						return nil, fmt.Errorf("dynamic volume expansion blocked for init container: %w", err)
					}
					composeVol := ComposeVolume{
						Type:   "bind",
						Source: dir,
						Target: vol.TargetPrefix + dir,
					}
					initSvc.Volumes = append(initSvc.Volumes, composeVol)
				}
				continue
			}

			source := vol.Source
			composeVol := ComposeVolume{
				Type:     "bind",
				Source:   source,
				Target:   vol.Target,
				ReadOnly: true, // Force read-only
			}
			initSvc.Volumes = append(initSvc.Volumes, composeVol)
		}

		// Inject environment variables into init container
		var envKeys []string
		for k := range envMap {
			// Init containers only need custom configuration vars.
			isCore := false
			for _, coreVar := range CoreEnvVars {
				if k == coreVar {
					isCore = true
					break
				}
			}
			if !isCore {
				envKeys = append(envKeys, k)
			}
		}
		sortEnvKeys(envKeys)
		for _, k := range envKeys {
			initSvc.Environment = append(initSvc.Environment, envEntry(k, envMap[k]))
		}

		compose.Services = append(compose.Services, NamedService{
			Name:    ic.Name,
			Service: initSvc,
		})
	}

	// -----------------------------------------------------------------
	// MAIN SENSOR SERVICE
	// -----------------------------------------------------------------
	containerName := sensorID
	if !strings.HasPrefix(containerName, "ts-") {
		containerName = "ts-" + containerName
	}

	svc := &ComposeService{
		Image:         buildImageString(m.Deployment.ImageRepository, m.Deployment.ImageTag, m.Deployment.ImageDigest),
		ContainerName: containerName,
		Restart:       "unless-stopped",

		// GLOBAL SANDBOX BASELINE Unconditionally
		ReadOnly:    true,
		CapDrop:     []string{"ALL"},
		SecurityOpt: []string{"no-new-privileges:true"},

		Logging: &LoggingConfig{
			Driver: "json-file",
			Options: map[string]string{
				"max-size": "10m",
				"max-file": "3",
			},
		},
	}

	// Network Mode
	svc.NetworkMode = m.Deployment.NetworkMode
	if svc.NetworkMode == "" {
		svc.NetworkMode = "bridge"
	}

	// User
	if m.Deployment.User != "" {
		svc.User = m.Deployment.User
	} else {
		// SECURITY MODEL: default to non-root UID to prevent implicit root execution
		// Docker does NOT guarantee non-root when User is omitted.
		svc.User = "65532:65532" // distroless "nonroot"; UID 1000 is usually a real login user on the host
	}

	// CapAdd: defensive filtering against allowlist
	svc.CapAdd = []string{}
	for _, cap := range m.Deployment.CapAdd {
		if security.AllowedCaps[cap] {
			svc.CapAdd = append(svc.CapAdd, cap)
		}
	}

	// Dependencies
	if len(initContainers) > 0 {
		svc.DependsOn = make(map[string]DependsOn)
		for _, ic := range initContainers {
			svc.DependsOn[ic.Name] = DependsOn{
				Condition: "service_completed_successfully",
			}
		}
	}

	// Environment Variables Assignment
	var envKeys []string
	for k := range envMap {
		envKeys = append(envKeys, k)
	}
	sortEnvKeys(envKeys)
	for _, k := range envKeys {
		svc.Environment = append(svc.Environment, envEntry(k, envMap[k]))
	}

	// Volumes
	var vols []models.VolumeMount
	vols = append(vols, m.Deployment.VolumeMounts...)
	sort.Slice(vols, func(i, j int) bool {
		return vols[i].Target < vols[j].Target
	})

	for _, vol := range vols {
		if vol.Type == models.DynamicFileBind {
			filesStr := envMap[vol.SourceEnv]
			files := strings.Split(filesStr, ",")
			var parsedFiles []string
			for _, f := range files {
				f = strings.TrimSpace(f)
				if f != "" {
					parsedFiles = append(parsedFiles, f)
				}
			}
			sort.Strings(parsedFiles)
			for _, f := range parsedFiles {
				if err := security.ValidateMountPath(f); err != nil {
					return nil, fmt.Errorf("dynamic volume expansion blocked for main sensor: %w", err)
				}
				composeVol := ComposeVolume{
					Type:     "bind",
					Source:   f,
					Target:   vol.TargetPrefix + f,
					ReadOnly: true, // Force read-only
				}
				svc.Volumes = append(svc.Volumes, composeVol)
			}
			continue
		}

		source := vol.Source
		composeVol := ComposeVolume{
			Type:     "bind",
			Source:   source,
			Target:   vol.Target,
			ReadOnly: true, // Force read-only
		}
		svc.Volumes = append(svc.Volumes, composeVol)
	}

	// Ports
	if svc.NetworkMode != "host" && len(m.Deployment.PortAssignments) > 0 {
		var ports []models.PortAssignment
		ports = append(ports, m.Deployment.PortAssignments...)
		sort.Slice(ports, func(i, j int) bool {
			return ports[i].Default < ports[j].Default
		})
		for _, p := range ports {
			svc.Ports = append(svc.Ports, fmt.Sprintf("%d:%d", p.Default, p.Default))
		}
	}

	compose.Services = append(compose.Services, NamedService{
		Name:    sensorID,
		Service: svc,
	})

	return &compose, nil
}

// envEntry renders KEY=value for compose. Docker Compose interpolates "$" in
// environment values, so it is escaped as "$$" to deliver values (banners,
// passwords, regexes) to the container verbatim.
func envEntry(k, v string) string {
	return k + "=" + strings.ReplaceAll(v, "$", "$$")
}

func sortEnvKeys(keys []string) {
	sort.Slice(keys, func(i, j int) bool {
		k1 := keys[i]
		k2 := keys[j]

		idx1 := -1
		idx2 := -1

		for idx, val := range CoreEnvVars {
			if k1 == val {
				idx1 = idx
			}
			if k2 == val {
				idx2 = idx
			}
		}

		if idx1 != -1 && idx2 != -1 {
			return idx1 < idx2
		}
		if idx1 != -1 {
			return true
		}
		if idx2 != -1 {
			return false
		}
		return k1 < k2
	})
}
