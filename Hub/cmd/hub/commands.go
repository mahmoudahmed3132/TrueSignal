package main

import (
	"fmt"
	"os"
	"time"

	"github.com/truesignal/hub/internal/services/auth"
	"github.com/truesignal/hub/internal/services/config"
	"github.com/truesignal/hub/internal/store"
)

// runCommand handles one-shot maintenance commands, run inside the Hub
// container (distroless, no shell), e.g.:
//
//	docker compose run --rm truesignal-hub /app/truesignal-hub mfa-reset
func runCommand(cfg *config.Config, args []string) int {
	switch args[0] {
	case "mfa-reset":
		return mfaReset(cfg)
	case "help", "-h", "--help":
		fmt.Println("usage: truesignal-hub [mfa-reset]")
		fmt.Println("  mfa-reset  remove the admin's MFA (lost authenticator and recovery codes).")
		fmt.Println("             The reset is sent to the SIEM as an audit record on the next Hub start.")
		return 0
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q (try help)\n", args[0])
		return 2
	}
}

// mfaReset is the break-glass path for a lost authenticator. Anyone who can
// run it already controls the Hub's database, so it adds no access; it is
// audited so the reset cannot go unnoticed.
func mfaReset(cfg *config.Config) int {
	st, err := store.NewStore(cfg.DBPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "open %s: %v\n", cfg.DBPath, err)
		return 1
	}
	defer st.DB.Close()
	if err := auth.ClearMFA(st); err != nil {
		fmt.Fprintf(os.Stderr, "reset failed: %v\n", err)
		return 1
	}
	at := time.Now().UTC().Format(time.RFC3339)
	if err := st.UpdateConfigValue(auth.MFAResetKey, at); err != nil {
		fmt.Fprintf(os.Stderr, "reset done, but recording it for the audit log failed: %v\n", err)
		return 1
	}
	fmt.Printf("Admin MFA removed at %s. Log in with the password and enroll again.\n", at)
	if cfg.RequireMFA {
		fmt.Println("TS_REQUIRE_MFA is on: the next login will be asked to enroll before anything else.")
	}
	fmt.Println("Restart the Hub to send the audit record to the SIEM.")
	return 0
}
