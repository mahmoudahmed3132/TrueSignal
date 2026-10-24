package main

import (
	"encoding/binary"
	"strconv"
	"strings"

	sdk "github.com/truesignal/sdk-go"
	"github.com/truesignal/sdk-go/decoy"
)

// DNS is log-only. The decoy parses the first question, records it and
// answers REFUSED with the question echoed (same size as the query, so no
// amplification). It never resolves or forwards anything.

var dnsTypes = map[uint16]string{
	1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA",
	33: "SRV", 64: "SVCB", 65: "HTTPS", 252: "AXFR", 255: "ANY",
}

// parseQuestion returns the first question's name, type and the offset just
// past it.
func parseQuestion(p []byte) (name string, qtype uint16, end int, ok bool) {
	if len(p) < 12 || binary.BigEndian.Uint16(p[4:]) == 0 {
		return "", 0, 0, false
	}
	pos := 12
	var labels []string
	for {
		if pos >= len(p) {
			return "", 0, 0, false
		}
		l := int(p[pos])
		pos++
		if l == 0 {
			break
		}
		if l&0xC0 != 0 || pos+l > len(p) || len(labels) > 127 { // no compression in a question
			return "", 0, 0, false
		}
		labels = append(labels, string(p[pos:pos+l]))
		pos += l
	}
	if pos+4 > len(p) {
		return "", 0, 0, false
	}
	qtype = binary.BigEndian.Uint16(p[pos:])
	name = strings.Join(labels, ".")
	if name == "" {
		name = "."
	}
	return name, qtype, pos + 4, true
}

func (h *handler) handleDNS(p []byte, src string) []byte {
	if len(p) < 12 || p[2]&0x80 != 0 { // ignore responses
		return nil
	}
	name, qtype, end, ok := parseQuestion(p)
	if !ok {
		return nil
	}
	typ, known := dnsTypes[qtype]
	if !known {
		typ = "TYPE" + strconv.Itoa(int(qtype))
	}
	severity := "medium"
	if qtype == 252 { // zone transfer attempt
		severity = "high"
	}
	if !h.report(severity, "dns_query", src, sdk.EventDetails{
		{Key: "query_name", Value: decoy.Sanitize(name, 256)},
		{Key: "query_type", Value: typ},
	}) {
		return nil
	}

	// Header + the single question, flags: QR, opcode copied, RD copied,
	// RA=0, RCODE=5 (REFUSED).
	resp := make([]byte, end)
	copy(resp, p[:end])
	resp[2] = 0x80 | (p[2] & 0x79)
	resp[3] = 0x05
	binary.BigEndian.PutUint16(resp[4:], 1)
	binary.BigEndian.PutUint16(resp[6:], 0)
	binary.BigEndian.PutUint16(resp[8:], 0)
	binary.BigEndian.PutUint16(resp[10:], 0)
	return resp
}
