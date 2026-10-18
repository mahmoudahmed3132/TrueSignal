package cli

import (
	"fmt"
)

func ShowOnboarding() error {
	fmt.Printf("\n%s%s=== TrueSignal Wizard ===%s\n\n", Bold, Cyan, Reset)
	fmt.Printf("    %sNo node provisioned.%s\n\n", Red, Reset)
	fmt.Printf("    Get started:\n\n")
	fmt.Printf("      %struesignal --link https://hub.example.com%s\n", Cyan, Reset)
	fmt.Printf("        Create a new node and link to Hub\n\n")
	fmt.Printf("      %struesignal --link https://hub.example.com --api-key <key>%s\n", Cyan, Reset)
	fmt.Printf("        Link to an existing node\n\n")
	fmt.Printf("    Then run:\n\n")
	fmt.Printf("      %struesignal apply%s      Reconcile node against Hub's desired state\n", Cyan, Reset)
	fmt.Printf("      %struesignal discover%s   Find and recommend sensors\n", Cyan, Reset)
	fmt.Printf("      %struesignal status%s     View node state\n\n", Cyan, Reset)
	return nil
}
