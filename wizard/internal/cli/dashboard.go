package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/truesignal/wizard/core/api"
	"golang.org/x/term"
)

// DashboardLogin signs in to the Hub dashboard and, when the Hub has admin
// MFA enabled, asks for a code: TS_DASHBOARD_MFA_CODE if set (one use, for
// scripted runs within its 30-second window), otherwise an interactive prompt.
func DashboardLogin(ctx context.Context, hub *api.HubClient, password string) (string, error) {
	cookie, err := hub.AuthenticateDashboard(ctx, password)
	if !errors.Is(err, api.ErrMFARequired) {
		return cookie, err
	}
	code := strings.TrimSpace(os.Getenv("TS_DASHBOARD_MFA_CODE"))
	if code == "" {
		if !term.IsTerminal(int(os.Stdin.Fd())) {
			return "", fmt.Errorf("the Hub requires an MFA code: run interactively or set TS_DASHBOARD_MFA_CODE")
		}
		code, err = ReadPasswordMasked("Enter MFA code (authenticator app or recovery code): ")
		if err != nil {
			return "", err
		}
	}
	return hub.AuthenticateDashboardCode(ctx, password, strings.TrimSpace(code))
}
