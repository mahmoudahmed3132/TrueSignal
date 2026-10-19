package security

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/truesignal/hub/internal/models"
)

// AllowedCaps is the complete set of Linux capabilities a sensor or init
// container may request. NET_ADMIN is intentionally absent: combined with the
// host network namespace it grants control of host routing and firewalls, and
// no official sensor needs it.
var AllowedCaps = map[string]bool{
	"NET_RAW":          true,
	"NET_BIND_SERVICE": true,
	"DAC_OVERRIDE":     true,
}

// allowedNetworkModes excludes container:<id> / service:<name>, which would
// join another workload's network namespace.
var allowedNetworkModes = map[string]bool{
	"":       true,
	"host":   true,
	"bridge": true,
	"none":   true,
}

// forbiddenMountPrefixes covers host control surfaces. /run and /var/run are
// blocked whole: on modern distros /var/run is a symlink to /run, and both hold
// the Docker/containerd sockets.
var forbiddenMountPrefixes = []string{
	"/var/run",
	"/run",
	"/proc",
	"/sys",
	"/dev",
	"/boot",
	"/etc",
	"/root",
	"/usr",
	"/bin",
	"/sbin",
	"/lib",
	"/lib32",
	"/lib64",
	"/var/lib/docker",
	"/var/lib/containerd",
	"/var/lib/kubelet",
}

func containsInterpolation(s string) bool {
	return strings.Contains(s, "$") || strings.Contains(s, "{{")
}

func ValidateManifest(m models.SensorManifest) error {
	// Privilege Check
	for _, cap := range m.Deployment.CapAdd {
		if !AllowedCaps[cap] {
			return fmt.Errorf("SECURITY REJECT: capability not allowed: %s", cap)
		}
	}
	for _, ic := range m.Deployment.InitContainers {
		for _, cap := range ic.CapAdd {
			if !AllowedCaps[cap] {
				return fmt.Errorf("SECURITY REJECT: capability not allowed in init container: %s", cap)
			}
		}
	}

	// Interpolation Checks
	if containsInterpolation(m.Deployment.ImageRepository) || containsInterpolation(m.Deployment.ImageTag) || containsInterpolation(m.Deployment.ImageDigest) {
		return fmt.Errorf("SECURITY REJECT: interpolation not allowed in image fields")
	}
	if containsInterpolation(m.Deployment.NetworkMode) {
		return fmt.Errorf("SECURITY REJECT: interpolation not allowed in network_mode")
	}
	for _, vol := range m.Deployment.VolumeMounts {
		if containsInterpolation(vol.Source) || containsInterpolation(vol.Target) {
			return fmt.Errorf("SECURITY REJECT: interpolation not allowed in volume mounts")
		}
	}
	for _, ic := range m.Deployment.InitContainers {
		if containsInterpolation(ic.ImageRepository) || containsInterpolation(ic.ImageTag) || containsInterpolation(ic.ImageDigest) {
			return fmt.Errorf("SECURITY REJECT: interpolation not allowed in init container image fields")
		}
		if containsInterpolation(ic.Command) {
			return fmt.Errorf("SECURITY REJECT: interpolation not allowed in init container command")
		}
		for _, vol := range ic.VolumeMounts {
			if containsInterpolation(vol.Source) || containsInterpolation(vol.Target) {
				return fmt.Errorf("SECURITY REJECT: interpolation not allowed in init container volume mounts")
			}
		}
	}

	if !allowedNetworkModes[m.Deployment.NetworkMode] {
		return fmt.Errorf("SECURITY REJECT: network_mode not allowed: %q", m.Deployment.NetworkMode)
	}

	// Host Escape Checks
	if err := checkVolumeMounts(m.Deployment.VolumeMounts); err != nil {
		return err
	}

	for _, initContainer := range m.Deployment.InitContainers {
		if err := checkVolumeMounts(initContainer.VolumeMounts); err != nil {
			return err
		}
	}

	return nil
}

// RequirePinnedImages enforces immutable, digest-pinned pulls for the main and
// init images. The registry pipeline injects digests at publish time, so an
// unpinned manifest means it did not come through that pipeline.
func RequirePinnedImages(m models.SensorManifest) error {
	if !strings.HasPrefix(m.Deployment.ImageDigest, "sha256:") {
		return fmt.Errorf("SECURITY REJECT: image %s is not pinned to a sha256 digest", m.Deployment.ImageRepository)
	}
	for _, ic := range m.Deployment.InitContainers {
		if !strings.HasPrefix(ic.ImageDigest, "sha256:") {
			return fmt.Errorf("SECURITY REJECT: init image %s is not pinned to a sha256 digest", ic.ImageRepository)
		}
	}
	return nil
}

// ValidateMountPath rejects relative paths, the host root, path tricks and any
// path under a forbidden prefix.
func ValidateMountPath(path string) error {
	if path == "" || strings.ContainsAny(path, "\x00\n\r") {
		return fmt.Errorf("SECURITY REJECT: invalid mount path %q", path)
	}
	if !filepath.IsAbs(path) {
		return fmt.Errorf("SECURITY REJECT: mount path must be absolute: %s", path)
	}
	cleanSource := filepath.Clean(path)
	if cleanSource == "/" {
		return fmt.Errorf("SECURITY REJECT: mounting the host root is forbidden")
	}
	for _, prefix := range forbiddenMountPrefixes {
		if cleanSource == prefix || strings.HasPrefix(cleanSource, prefix+"/") {
			return fmt.Errorf("SECURITY REJECT: mount path is forbidden: %s", path)
		}
	}
	return nil
}

func checkVolumeMounts(mounts []models.VolumeMount) error {
	for _, vol := range mounts {
		// Dynamic mounts take their source from an env var at build time and
		// are validated per path by the builder.
		if vol.Type == models.DynamicDirBind || vol.Type == models.DynamicFileBind {
			continue
		}
		if err := ValidateMountPath(vol.Source); err != nil {
			return err
		}
	}
	return nil
}
