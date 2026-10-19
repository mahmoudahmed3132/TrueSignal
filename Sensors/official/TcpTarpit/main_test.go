package main

import "testing"

func TestParsePortBanners(t *testing.T) {
	m := parsePortBanners(`22=SSH-2.0-OpenSSH_8.2p1\r\n; 3306= ;bad;99999=x;x=y`)
	if m[22] != "SSH-2.0-OpenSSH_8.2p1\r\n" {
		t.Errorf("port 22 banner = %q", m[22])
	}
	if b, ok := m[3306]; !ok || b != "" {
		t.Errorf("explicit empty banner for 3306 must be kept as silence, got %q (present=%v)", b, ok)
	}
	if _, ok := m[99999]; ok {
		t.Error("out-of-range port must be ignored")
	}
}

func TestBannerForFallsBackToGlobal(t *testing.T) {
	portBanners = map[int]string{2222: "SSH-x\r\n"}
	banner = "GLOBAL"
	if bannerFor(2222) != "SSH-x\r\n" || bannerFor(3306) != "GLOBAL" {
		t.Errorf("unexpected banner selection")
	}
}

func TestParsePortsRejectsInvalid(t *testing.T) {
	got := parsePorts("0,22,70000,abc,2222")
	if len(got) != 2 || got[0] != 22 || got[1] != 2222 {
		t.Errorf("parsePorts = %v", got)
	}
}
