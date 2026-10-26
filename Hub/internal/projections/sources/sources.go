// Package sources profiles attacker sources across all events: how often
// and how widely each one touched the decoys, and which operator lists it is
// on now. The dashboard's triage labels and filters are built from it.
package sources

import (
	"net/netip"
	"sort"

	"github.com/truesignal/hub/internal/services/sourcelist"
	"github.com/truesignal/hub/internal/store"
)

// Profile is one source's activity and current classification.
type Profile struct {
	Source       string `json:"source"`
	Events       int    `json:"events"`
	Decoys       int    `json:"decoys"`
	FirstSeen    string `json:"firstSeen"`
	LastSeen     string `json:"lastSeen"`
	IsIP         bool   `json:"isIp"`
	Internal     bool   `json:"internal"`
	Whitelisted  bool   `json:"whitelisted"`
	KnownScanner bool   `json:"knownScanner"`
}

var internalRanges = func() []netip.Prefix {
	var out []netip.Prefix
	for _, c := range []string{
		"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", // RFC 1918
		"100.64.0.0/10",  // RFC 6598 shared address space
		"127.0.0.0/8",    // loopback
		"169.254.0.0/16", // link-local
		"fc00::/7",       // unique local
		"fe80::/10",      // link-local
		"::1/128",
	} {
		out = append(out, netip.MustParsePrefix(c))
	}
	return out
}()

// Classify returns whether source is an IP address and, if so, whether it
// is in a private, loopback or link-local range.
func Classify(source string) (isIP, internal bool) {
	a, err := netip.ParseAddr(source)
	if err != nil {
		if ap, err := netip.ParseAddrPort(source); err == nil {
			a = ap.Addr()
		} else {
			return false, false
		}
	}
	a = a.Unmap()
	for _, p := range internalRanges {
		if p.Contains(a) {
			return true, true
		}
	}
	return true, false
}

// Build profiles every source, busiest first.
func Build(rows []store.SourceActivity, whitelist, scanners *sourcelist.List) []Profile {
	out := make([]Profile, 0, len(rows))
	for _, r := range rows {
		isIP, internal := Classify(r.Source)
		out = append(out, Profile{
			Source:       r.Source,
			Events:       r.Events,
			Decoys:       r.Decoys,
			FirstSeen:    r.FirstSeen,
			LastSeen:     r.LastSeen,
			IsIP:         isIP,
			Internal:     internal,
			Whitelisted:  whitelist.Match(r.Source),
			KnownScanner: scanners.Match(r.Source),
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Events != out[j].Events {
			return out[i].Events > out[j].Events
		}
		return out[i].Source < out[j].Source
	})
	return out
}
