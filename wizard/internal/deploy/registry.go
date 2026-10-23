package deploy

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// RegistryConfigDir is a Docker client config used only by TrueSignal, so
// the image pull credential stays out of root's ~/.docker and out of the
// sensor containers (which never receive it).
const RegistryConfigDir = "/etc/truesignal/docker"

// DefaultRegistry hosts the official sensor images.
const DefaultRegistry = "ghcr.io"

var (
	registryHostPattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9.-]*[a-z0-9])?(:[0-9]{1,5})?$`)
	registryUserPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$`)
)

// ValidateRegistryCredential rejects values that could be read as docker
// flags or that cannot be a registry login.
func ValidateRegistryCredential(registry, user, token string) error {
	if !registryHostPattern.MatchString(registry) {
		return fmt.Errorf("invalid registry host %q", registry)
	}
	if !registryUserPattern.MatchString(user) {
		return fmt.Errorf("invalid registry username %q", user)
	}
	if token == "" || strings.ContainsAny(token, " \t\r\n") {
		return fmt.Errorf("registry token is empty or contains whitespace")
	}
	return nil
}

// hasRegistryLogin reports whether a TrueSignal registry login exists.
func hasRegistryLogin() bool {
	_, err := os.Stat(filepath.Join(RegistryConfigDir, "config.json"))
	return err == nil
}

// linkCLIPlugins exposes a manually installed compose plugin
// (~/.docker/cli-plugins) to commands run with DOCKER_CONFIG, which
// otherwise only searches $DOCKER_CONFIG/cli-plugins and system paths.
func linkCLIPlugins() {
	home, err := os.UserHomeDir()
	if err != nil {
		return
	}
	src := filepath.Join(home, ".docker", "cli-plugins")
	if fi, err := os.Stat(src); err != nil || !fi.IsDir() {
		return
	}
	dst := filepath.Join(RegistryConfigDir, "cli-plugins")
	if _, err := os.Lstat(dst); err == nil {
		return
	}
	_ = os.Symlink(src, dst)
}

// dockerEnv is the environment for docker commands that may pull images.
// Without a TrueSignal login it is the plain process environment.
func dockerEnv() []string {
	env := os.Environ()
	if !hasRegistryLogin() {
		return env
	}
	linkCLIPlugins()
	return append(env, "DOCKER_CONFIG="+RegistryConfigDir)
}

// RegistryLogin stores a pull credential for registry in RegistryConfigDir.
// The token reaches docker on stdin, never in argv.
func RegistryLogin(registry, user, token string) error {
	if err := ValidateRegistryCredential(registry, user, token); err != nil {
		return err
	}
	if err := os.MkdirAll(RegistryConfigDir, 0700); err != nil {
		return fmt.Errorf("failed to create %s: %w", RegistryConfigDir, err)
	}
	if err := os.Chmod(RegistryConfigDir, 0700); err != nil {
		return fmt.Errorf("failed to restrict %s: %w", RegistryConfigDir, err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// codeql[go/command-injection] Arguments validated by ValidateRegistryCredential.
	// nosemgrep: go.lang.security.audit.dangerous-exec-command.dangerous-exec-command
	cmd := exec.CommandContext(ctx, "docker", "--config", RegistryConfigDir, "login", "--username", user, "--password-stdin", registry)
	cmd.Stdin = strings.NewReader(token)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("docker login to %s failed: %v: %s", registry, err, strings.TrimSpace(string(out)))
	}

	cfg := filepath.Join(RegistryConfigDir, "config.json")
	if err := os.Chmod(cfg, 0600); err != nil {
		return fmt.Errorf("failed to restrict %s: %w", cfg, err)
	}
	return nil
}

// RegistryLogout removes the TrueSignal registry credential.
func RegistryLogout() error {
	if err := os.RemoveAll(RegistryConfigDir); err != nil {
		return fmt.Errorf("failed to remove %s: %w", RegistryConfigDir, err)
	}
	return nil
}
