package main

import (
	"syscall"
	"testing"
)

func TestSkipFrame(t *testing.T) {
	cases := []struct {
		ll          *syscall.SockaddrLinklayer
		ignoreLocal bool
		want        bool
	}{
		{&syscall.SockaddrLinklayer{Pkttype: syscall.PACKET_OUTGOING, Ifindex: 2}, false, true},
		{&syscall.SockaddrLinklayer{Pkttype: syscall.PACKET_HOST, Ifindex: 2}, true, false},
		{&syscall.SockaddrLinklayer{Pkttype: syscall.PACKET_HOST, Ifindex: 1}, true, true},
		{&syscall.SockaddrLinklayer{Pkttype: syscall.PACKET_HOST, Ifindex: 1}, false, false},
		{nil, true, false},
	}
	for i, c := range cases {
		if got := skipFrame(c.ll, c.ignoreLocal, 1); got != c.want {
			t.Errorf("case %d: got %v want %v", i, got, c.want)
		}
	}
}

func TestAnalyzePacket(t *testing.T) {
	if tool, kind := analyzePacket(0x02, 1024); tool != "Likely Nmap / Masscan" || kind != "Stealth SYN Port Scan" {
		t.Errorf("SYN with scanner window: %s / %s", tool, kind)
	}
	if _, kind := analyzePacket(0x29, 0); kind != "Stealth XMAS Scan" {
		t.Errorf("XMAS: %s", kind)
	}
	if _, kind := analyzePacket(0x2B, 0); kind != "OS Detection Probe (T3)" {
		t.Errorf("T3: %s", kind)
	}
}
