package deploy

import "testing"

func TestValidateRegistryCredential(t *testing.T) {
	ok := []struct{ reg, user, tok string }{
		{"ghcr.io", "truesignal-pull", "ghp_abc123"},
		{"registry.example.com:5000", "bot.user", "x"},
	}
	for _, c := range ok {
		if err := ValidateRegistryCredential(c.reg, c.user, c.tok); err != nil {
			t.Errorf("%v: unexpected error %v", c, err)
		}
	}
	bad := []struct{ reg, user, tok string }{
		{"--config=/tmp", "u", "t"},
		{"ghcr.io/evil", "u", "t"},
		{"GHCR.IO", "u", "t"},
		{"ghcr.io", "-p", "t"},
		{"ghcr.io", "", "t"},
		{"ghcr.io", "u", ""},
		{"ghcr.io", "u", "tok\nen"},
		{"ghcr.io", "u", "tok en"},
	}
	for _, c := range bad {
		if err := ValidateRegistryCredential(c.reg, c.user, c.tok); err == nil {
			t.Errorf("%v: expected error", c)
		}
	}
}
