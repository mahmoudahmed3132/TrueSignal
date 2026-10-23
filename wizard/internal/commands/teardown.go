package commands

import (
	"fmt"
	"os"

	"github.com/truesignal/wizard/internal/app"
	"github.com/truesignal/wizard/internal/cli"
	"github.com/truesignal/wizard/internal/deploy"
)

func HandleTeardown(force bool) error {
	cli.PrintSectionHeader("TrueSignal Sensor Teardown", cli.Red)

	fmt.Printf("This action will perform the following destructive operations:\n")
	fmt.Printf("  %s-%s Stop and remove all Docker containers in the '%s' project\n", cli.Red, cli.Reset, deploy.ProjectName)
	fmt.Printf("  %s-%s Remove the configuration directory: %s\n", cli.Red, cli.Reset, deploy.DeployDir)
	fmt.Printf("  %s-%s Delete the node identity file: %s\n", cli.Red, cli.Reset, app.ConfigPath)
	fmt.Printf("  %s-%s Delete the image registry credential: %s\n", cli.Red, cli.Reset, deploy.RegistryConfigDir)
	fmt.Printf("  %s-%s Note: The node entry remains in the Hub. Delete it from the Dashboard if needed.%s\n\n", cli.Dim, cli.Reset, cli.Reset)

	if !cli.ConfirmAction("Are you absolutely sure you want to permanently remove TrueSignal from this host?", force) {
		fmt.Printf("\n%sTeardown aborted.%s\n\n", cli.Dim, cli.Reset)
		return nil
	}

	lures := deploy.ConfiguredDecoyFiles()

	fmt.Printf("\n%s[*] Tearing down isolated Docker environment...%s\n", cli.Dim, cli.Reset)
	if err := deploy.Uninstall(); err != nil {
		fmt.Printf("%s[!] Docker teardown encountered an issue: %v%s\n", cli.Yellow, err, cli.Reset)
	}

	fmt.Printf("%s[*] Removing identity file (%s)...%s\n", cli.Dim, app.ConfigPath, cli.Reset)
	if err := os.Remove(app.ConfigPath); err != nil && !os.IsNotExist(err) {
		fmt.Printf("%s[!] Failed to remove config file: %v%s\n", cli.Yellow, err, cli.Reset)
	}

	fmt.Printf("%s[*] Removing registry credential (%s)...%s\n", cli.Dim, deploy.RegistryConfigDir, cli.Reset)
	if err := deploy.RegistryLogout(); err != nil {
		fmt.Printf("%s[!] %v%s\n", cli.Yellow, err, cli.Reset)
	}

	fmt.Printf("\n%s[*] Removing TrueSignal CLI binary...%s\n", cli.Dim, cli.Reset)
	if execPath, err := os.Executable(); err == nil {
		if err := os.Remove(execPath); err != nil && !os.IsNotExist(err) {
			fmt.Printf("%s[!] Failed to remove CLI binary (%s): %v%s\n", cli.Yellow, execPath, err, cli.Reset)
		}
	}

	fmt.Printf("\n%s✅ All TrueSignal sensors, configurations, and the CLI tool have been successfully removed.%s\n\n", cli.Green, cli.Reset)
	if len(lures) > 0 {
		fmt.Printf("%sLure files were left in place (they may be pre-existing host files). Review and delete as appropriate:%s\n", cli.Yellow, cli.Reset)
		for _, f := range lures {
			fmt.Printf("    %s\n", f)
		}
		fmt.Println()
	}
	return nil
}
