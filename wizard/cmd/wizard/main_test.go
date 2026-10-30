package main

import "testing"

func TestWantsHelp(t *testing.T) {
	for _, args := range [][]string{{"discover", "--help"}, {"apply", "-h"}, {"help"}, {"uninstall", "-help"}} {
		if !wantsHelp(args) {
			t.Errorf("%v not treated as help", args)
		}
	}
	for _, args := range [][]string{nil, {"discover"}, {"relink", "--force"}} {
		if wantsHelp(args) {
			t.Errorf("%v treated as help", args)
		}
	}
}
