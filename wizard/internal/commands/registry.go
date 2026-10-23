package commands

import (
	"fmt"
	"os"
	"strings"

	"github.com/truesignal/wizard/internal/cli"
	"github.com/truesignal/wizard/internal/deploy"
)

// registryFromEnv reads the image pull credential from TS_REGISTRY,
// TS_REGISTRY_USER and TS_REGISTRY_TOKEN. ok is false when no token is set.
func registryFromEnv() (registry, user, token string, ok bool) {
	registry = strings.TrimSpace(os.Getenv("TS_REGISTRY"))
	if registry == "" {
		registry = deploy.DefaultRegistry
	}
	user = strings.TrimSpace(os.Getenv("TS_REGISTRY_USER"))
	token = strings.TrimSpace(os.Getenv("TS_REGISTRY_TOKEN"))
	return registry, user, token, token != ""
}

// loginFromEnvIfSet logs in to the image registry when TS_REGISTRY_TOKEN is
// set, so a first apply during --link can pull private images.
func loginFromEnvIfSet() error {
	registry, user, token, ok := registryFromEnv()
	if !ok {
		return nil
	}
	if user == "" {
		return fmt.Errorf("TS_REGISTRY_TOKEN is set but TS_REGISTRY_USER is empty")
	}
	fmt.Printf("%s[*] Logging in to %s as %s...%s\n", cli.Dim, registry, user, cli.Reset)
	if err := deploy.RegistryLogin(registry, user, token); err != nil {
		return err
	}
	fmt.Printf("%s[*] Registry credential stored in %s.%s\n", cli.Green, deploy.RegistryConfigDir, cli.Reset)
	return nil
}

// HandleRegistryLogin stores (or rotates) the image pull credential.
func HandleRegistryLogin() error {
	cli.PrintSectionHeader("TrueSignal Registry Login", cli.Cyan)

	registry, user, token, ok := registryFromEnv()
	if !ok {
		if !cli.IsTerminal() {
			return fmt.Errorf("set TS_REGISTRY_USER and TS_REGISTRY_TOKEN for non-interactive use")
		}
		if user == "" {
			user, _ = cli.PromptInput(fmt.Sprintf("    %s username: ", registry))
			user = strings.TrimSpace(user)
		}
		var err error
		token, err = cli.ReadPasswordMasked("    Token (read:packages): ")
		if err != nil {
			return fmt.Errorf("failed to read token: %w", err)
		}
		token = strings.TrimSpace(token)
	}
	if user == "" {
		return fmt.Errorf("registry username is required (TS_REGISTRY_USER)")
	}

	fmt.Printf("%s[*] Logging in to %s as %s...%s\n", cli.Dim, registry, user, cli.Reset)
	if err := deploy.RegistryLogin(registry, user, token); err != nil {
		return err
	}
	fmt.Printf("\n%s✅ Registry credential stored in %s. 'truesignal apply' will use it.%s\n\n", cli.Green, deploy.RegistryConfigDir, cli.Reset)
	return nil
}

// HandleRegistryLogout removes the image pull credential.
func HandleRegistryLogout() error {
	if err := deploy.RegistryLogout(); err != nil {
		return err
	}
	fmt.Printf("%s[*] Registry credential removed (%s).%s\n", cli.Green, deploy.RegistryConfigDir, cli.Reset)
	return nil
}
