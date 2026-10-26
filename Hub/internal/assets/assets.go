// Package assets holds the operator's inventory of protected hosts and
// ranges, and resolves an event source to the asset it belongs to. A decoy
// touched from a known asset names the real host that is likely
// compromised, and how much it matters.
package assets

import (
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"
	"sync"
)

const (
	// ConfigKey is where the inventory is stored (config table, JSON).
	ConfigKey = "assets"
	MaxAssets = 5000
	maxField  = 256
	maxTags   = 20
)

// Criticalities, lowest first.
var Criticalities = []string{"low", "medium", "high", "critical"}

// Asset is one inventory entry. Address is an IP or a CIDR range.
type Asset struct {
	Name        string   `json:"name"`
	Address     string   `json:"address"`
	Criticality string   `json:"criticality"`
	Owner       string   `json:"owner"`
	Tags        []string `json:"tags"`
}

// Ref is the part of an asset attached to events.
type Ref struct {
	Name        string `json:"name"`
	Criticality string `json:"criticality"`
}

// Validate normalises a submitted inventory: trims fields, canonicalises
// the address (an IP becomes /32 or /128 internally but is kept as
// written), defaults criticality to medium, and rejects duplicates,
// invalid addresses and oversized input.
func Validate(list []Asset) ([]Asset, error) {
	if len(list) > MaxAssets {
		return nil, fmt.Errorf("too many assets (%d, maximum %d)", len(list), MaxAssets)
	}
	seen := map[netip.Prefix]string{}
	out := make([]Asset, 0, len(list))
	for i, a := range list {
		a.Name = strings.TrimSpace(a.Name)
		a.Address = strings.TrimSpace(a.Address)
		a.Owner = strings.TrimSpace(a.Owner)
		a.Criticality = strings.ToLower(strings.TrimSpace(a.Criticality))
		row := fmt.Sprintf("asset %d", i+1)
		if a.Name == "" {
			return nil, fmt.Errorf("%s: name is required", row)
		}
		if len(a.Name) > maxField || len(a.Owner) > maxField || len(a.Address) > maxField {
			return nil, fmt.Errorf("%s (%s): field longer than %d characters", row, a.Name, maxField)
		}
		p, err := parseAddress(a.Address)
		if err != nil {
			return nil, fmt.Errorf("%s (%s): %v", row, a.Name, err)
		}
		if prev, dup := seen[p]; dup {
			return nil, fmt.Errorf("%s (%s): address %s already used by %s", row, a.Name, a.Address, prev)
		}
		seen[p] = a.Name
		if a.Criticality == "" {
			a.Criticality = "medium"
		}
		if !validCriticality(a.Criticality) {
			return nil, fmt.Errorf("%s (%s): criticality must be one of %s", row, a.Name, strings.Join(Criticalities, ", "))
		}
		tags := []string{}
		for _, t := range a.Tags {
			if t = strings.TrimSpace(t); t != "" {
				if len(t) > maxField {
					return nil, fmt.Errorf("%s (%s): tag longer than %d characters", row, a.Name, maxField)
				}
				tags = append(tags, t)
			}
		}
		if len(tags) > maxTags {
			return nil, fmt.Errorf("%s (%s): more than %d tags", row, a.Name, maxTags)
		}
		a.Tags = tags
		out = append(out, a)
	}
	return out, nil
}

func validCriticality(c string) bool {
	for _, v := range Criticalities {
		if c == v {
			return true
		}
	}
	return false
}

func parseAddress(s string) (netip.Prefix, error) {
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return netip.Prefix{}, fmt.Errorf("invalid CIDR range %q", s)
		}
		return p.Masked(), nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("invalid IP address %q", s)
	}
	a = a.Unmap()
	return netip.PrefixFrom(a, a.BitLen()), nil
}

// Index resolves sources to assets; the most specific range wins.
type Index struct {
	entries []entry
}

type entry struct {
	prefix netip.Prefix
	ref    Ref
}

// NewIndex builds an index; entries with invalid addresses are skipped
// (only possible if the stored JSON was edited by hand).
func NewIndex(list []Asset) *Index {
	ix := &Index{}
	for _, a := range list {
		p, err := parseAddress(a.Address)
		if err != nil {
			continue
		}
		ix.entries = append(ix.entries, entry{p, Ref{Name: a.Name, Criticality: a.Criticality}})
	}
	sort.SliceStable(ix.entries, func(i, j int) bool { return ix.entries[i].prefix.Bits() > ix.entries[j].prefix.Bits() })
	return ix
}

// Lookup returns the asset a source address belongs to, or nil. A source
// may carry a port; non-IP sources never match.
func (ix *Index) Lookup(source string) *Ref {
	if ix == nil || len(ix.entries) == 0 {
		return nil
	}
	a, err := netip.ParseAddr(strings.TrimSpace(source))
	if err != nil {
		host, _, err2 := net.SplitHostPort(strings.TrimSpace(source))
		if err2 != nil {
			return nil
		}
		if a, err = netip.ParseAddr(host); err != nil {
			return nil
		}
	}
	a = a.Unmap()
	for i := range ix.entries {
		if ix.entries[i].prefix.Contains(a) {
			r := ix.entries[i].ref
			return &r
		}
	}
	return nil
}

// Decode reads a stored inventory. Empty input is an empty inventory.
func Decode(raw string) ([]Asset, error) {
	if strings.TrimSpace(raw) == "" {
		return []Asset{}, nil
	}
	var list []Asset
	if err := json.Unmarshal([]byte(raw), &list); err != nil {
		return nil, err
	}
	return list, nil
}

// Cache rebuilds the index only when the stored JSON changes.
type Cache struct {
	mu  sync.Mutex
	raw string
	ix  *Index
}

// Get returns the index for the stored JSON; undecodable JSON gives an
// empty index.
func (c *Cache) Get(raw string) *Index {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.ix == nil || raw != c.raw {
		list, err := Decode(raw)
		if err != nil {
			list = nil
		}
		c.raw, c.ix = raw, NewIndex(list)
	}
	return c.ix
}
