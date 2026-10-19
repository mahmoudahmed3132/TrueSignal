package commands

import (
	"path/filepath"
	"testing"
)

func TestKeepPlaceableLures(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, ".env.backup") + ", /definitely/not/here/vpn_keys.txt,"
	if got := keepPlaceableLures(in); got != filepath.Join(dir, ".env.backup") {
		t.Fatalf("got %q", got)
	}
}
