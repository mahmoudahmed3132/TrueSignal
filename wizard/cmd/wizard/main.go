package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/truesignal/wizard/internal/cli"
	"github.com/truesignal/wizard/internal/commands"
	"github.com/truesignal/wizard/internal/system"
)

func main() {
	if err := run(); err != nil {

		// codeql[go/xss] Printing to CLI stdout/stderr, not HTTP.
		// nosemgrep: go.lang.security.audit.xss.no-fprintf-to-responsewriter.no-fprintf-to-responsewriter
		fmt.Fprintf(os.Stderr, "\n%sFatal Error: %v%s\n", cli.Red, err, cli.Reset)
		os.Exit(1)
	}
}

func run() error {
	cli.SetupUsage()

	forcePtr := flag.Bool("force", false, "Bypass confirmation prompts (useful for automation)")
	linkURL := flag.String("link", "", "Hub URL to link to (e.g., https://hub.truesignal.local)")
	apiKeyPtr := flag.String("api-key", "", "Node API key (for linking to an existing node). Prefer the TS_NODE_API_KEY env var: arguments are visible in the process list")
	aliasPtr := flag.String("alias", "", "Custom alias for this node (defaults to OS hostname)")
	tagsPtr := flag.String("tags", "", "Comma-separated tags for this node")

	flag.Parse()

	if warning, _ := system.CheckRoot(); warning != "" {
		return fmt.Errorf("TrueSignal wizard must be run as root (sudo) for system analysis and sensor deployment.")
	}

	if *linkURL != "" {
		apiKey := *apiKeyPtr
		if apiKey == "" {
			apiKey = os.Getenv("TS_NODE_API_KEY")
		}
		return commands.HandleLink(*linkURL, apiKey, *aliasPtr, *tagsPtr, *forcePtr)
	}

	args := flag.Args()
	if len(args) == 0 {
		return commands.HandleInteractiveMenu(*forcePtr)
	}

	switch args[0] {
	case "apply":
		return commands.HandleApply(*forcePtr)
	case "discover":
		return commands.HandleDiscover(*forcePtr)
	case "firedrill":
		return commands.HandleFiredrill()
	case "status":
		return commands.HandleStatus()
	case "relink":
		return commands.HandleRelink(args[1:], *forcePtr)
	case "registry-login":
		return commands.HandleRegistryLogin()
	case "registry-logout":
		return commands.HandleRegistryLogout()
	case "uninstall":
		return commands.HandleTeardown(*forcePtr)
	default:
		return fmt.Errorf("unknown command: %s", args[0])
	}
}
