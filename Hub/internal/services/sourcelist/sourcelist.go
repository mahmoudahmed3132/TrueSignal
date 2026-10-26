// Package sourcelist matches event sources against an operator list of IP
// addresses, CIDR ranges and plain source names (the whitelist and the
// known-scanner list).
package sourcelist

import (
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
)

const (
	// MaxEntries bounds a list so matching stays cheap on every event.
	MaxEntries = 10000
	// MaxEntryLen matches the Hub's clamp on event source fields.
	MaxEntryLen = 256
)

// List is a parsed source list. The zero value matches nothing.
type List struct {
	names    map[string]bool
	prefixes []netip.Prefix
}

// Split breaks a stored or pasted list into trimmed entries. Commas and
// newlines both separate entries; empty lines and lines starting with # are
// skipped, so an exported scanner list or a commented file imports as is.
func Split(raw string) []string {
	var out []string
	for _, line := range strings.Split(strings.ReplaceAll(raw, "\r", ""), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		for _, part := range strings.Split(line, ",") {
			if p := strings.TrimSpace(part); p != "" {
				out = append(out, p)
			}
		}
	}
	return out
}

// Parse validates and parses a list. An entry containing "/" must be a
// valid CIDR; an entry that parses as an IP matches that address in any
// notation; anything else matches the event source exactly.
func Parse(raw string) (*List, error) {
	return parse(raw, true)
}

// parse with strict=false never fails: an invalid CIDR becomes a plain name
// and limits are ignored. Stored lists use it, so a list saved before CIDR
// support (when "a/b" was just a name) keeps working.
func parse(raw string, strict bool) (*List, error) {
	entries := Split(raw)
	if strict && len(entries) > MaxEntries {
		return nil, fmt.Errorf("too many entries (%d, maximum %d)", len(entries), MaxEntries)
	}
	l := &List{names: map[string]bool{}}
	for _, e := range entries {
		if strict && len(e) > MaxEntryLen {
			return nil, fmt.Errorf("entry longer than %d characters: %.40q", MaxEntryLen, e)
		}
		if strings.Contains(e, "/") {
			p, err := netip.ParsePrefix(e)
			if err == nil {
				l.prefixes = append(l.prefixes, p.Masked())
				continue
			}
			if strict {
				return nil, fmt.Errorf("invalid CIDR range: %q", e)
			}
			l.names[e] = true
			continue
		}
		if a, err := netip.ParseAddr(e); err == nil {
			a = a.Unmap()
			l.prefixes = append(l.prefixes, netip.PrefixFrom(a, a.BitLen()))
			continue
		}
		l.names[e] = true
	}
	return l, nil
}

// Normalize returns the canonical stored form of a list: entries joined by
// ", ", duplicates removed, order kept. It assumes raw passed Parse.
func Normalize(raw string) string {
	seen := map[string]bool{}
	var out []string
	for _, e := range Split(raw) {
		if !seen[e] {
			seen[e] = true
			out = append(out, e)
		}
	}
	return strings.Join(out, ", ")
}

// Match reports whether source is on the list. A source may carry a port
// ("10.0.0.5:4431", "[fe80::1]:22"); the address part is matched.
func (l *List) Match(source string) bool {
	if l == nil {
		return false
	}
	source = strings.TrimSpace(source)
	if l.names[source] {
		return true
	}
	if len(l.prefixes) == 0 {
		return false
	}
	a, ok := parseSourceAddr(source)
	if !ok {
		return false
	}
	for _, p := range l.prefixes {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

func parseSourceAddr(source string) (netip.Addr, bool) {
	if a, err := netip.ParseAddr(source); err == nil {
		return a.Unmap(), true
	}
	if host, _, err := net.SplitHostPort(source); err == nil {
		if a, err := netip.ParseAddr(host); err == nil {
			return a.Unmap(), true
		}
	}
	return netip.Addr{}, false
}

// Cache re-parses a list only when its stored text changes. Lists live in
// the config table and are read on every event.
type Cache struct {
	mu   sync.Mutex
	raw  string
	list *List
}

// Get returns the parsed list for raw, parsed leniently (see parse).
func (c *Cache) Get(raw string) *List {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.list == nil || raw != c.raw {
		l, _ := parse(raw, false)
		c.raw, c.list = raw, l
	}
	return c.list
}
