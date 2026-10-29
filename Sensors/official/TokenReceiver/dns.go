package main

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	sdk "github.com/truesignal/sdk-go"
	"github.com/truesignal/sdk-go/decoy"
)

// The DNS side is a minimal authoritative server for TS_BEACON_DOMAIN only.
// It answers SOA and NS at the apex, A for the apex, the name servers and
// every name below the apex (when TS_ANSWER_IPV4 is set), and NODATA with the
// SOA otherwise. Names outside the zone are REFUSED: it never recurses or
// forwards, so it can't be used as an open resolver. Any label below the apex
// that is a valid beacon token raises beacon_triggered.

const (
	dnsTTL      = 60
	typeA       = 1
	typeNS      = 2
	typeSOA     = 6
	typeOPT     = 41
	classIN     = 1
	rcodeOK     = 0
	rcodeFormat = 1
	rcodeNotImp = 4
	rcodeRefuse = 5
	maxTCPQuery = 4096
)

var dnsTypes = map[uint16]string{
	1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA",
	33: "SRV", 64: "SVCB", 65: "HTTPS", 252: "AXFR", 255: "ANY",
}

type zone struct {
	domain string   // lowercase, no trailing dot
	ns     []string // name server host names
	ipv4   net.IP   // answer for A queries; nil means NODATA
}

// question is the first question of a query.
type question struct {
	labels []string // as sent (case preserved)
	qtype  uint16
	end    int // offset just past the question
}

func (q question) name() string {
	if len(q.labels) == 0 {
		return "."
	}
	return strings.Join(q.labels, ".")
}

func parseQuestion(p []byte) (question, bool) {
	if len(p) < 12 || binary.BigEndian.Uint16(p[4:]) != 1 {
		return question{}, false
	}
	pos := 12
	var q question
	for {
		if pos >= len(p) {
			return question{}, false
		}
		l := int(p[pos])
		pos++
		if l == 0 {
			break
		}
		if l&0xC0 != 0 || pos+l > len(p) || len(q.labels) > 127 { // no compression in a question
			return question{}, false
		}
		q.labels = append(q.labels, string(p[pos:pos+l]))
		pos += l
	}
	if pos+4 > len(p) {
		return question{}, false
	}
	q.qtype = binary.BigEndian.Uint16(p[pos:])
	q.end = pos + 4
	return q, true
}

// clientSubnet returns the EDNS Client Subnet (RFC 7871) of a query, if the
// resolver sent one: the network of the client behind a public resolver.
func clientSubnet(p []byte, from int) string {
	if len(p) < 12 {
		return ""
	}
	an, ns, ar := binary.BigEndian.Uint16(p[6:]), binary.BigEndian.Uint16(p[8:]), binary.BigEndian.Uint16(p[10:])
	pos := from
	for i := 0; i < int(an)+int(ns)+int(ar); i++ {
		next, rtype, rdata, ok := readRR(p, pos)
		if !ok {
			return ""
		}
		pos = next
		if i < int(an)+int(ns) || rtype != typeOPT {
			continue
		}
		for len(rdata) >= 4 {
			code, l := binary.BigEndian.Uint16(rdata), int(binary.BigEndian.Uint16(rdata[2:]))
			if 4+l > len(rdata) {
				return ""
			}
			opt := rdata[4 : 4+l]
			rdata = rdata[4+l:]
			if code != 8 || len(opt) < 4 {
				continue
			}
			family, prefix := binary.BigEndian.Uint16(opt), int(opt[2])
			addr := opt[4:]
			var ip net.IP
			switch family {
			case 1:
				if prefix > 32 || len(addr) > 4 {
					return ""
				}
				ip = make(net.IP, 4)
			case 2:
				if prefix > 128 || len(addr) > 16 {
					return ""
				}
				ip = make(net.IP, 16)
			default:
				return ""
			}
			copy(ip, addr)
			return ip.String() + "/" + strconv.Itoa(prefix)
		}
	}
	return ""
}

// readRR skips one resource record and returns its type and rdata.
func readRR(p []byte, pos int) (next int, rtype uint16, rdata []byte, ok bool) {
	for { // owner name, possibly compressed
		if pos >= len(p) {
			return 0, 0, nil, false
		}
		l := int(p[pos])
		if l == 0 {
			pos++
			break
		}
		if l&0xC0 == 0xC0 {
			pos += 2
			break
		}
		if l&0xC0 != 0 {
			return 0, 0, nil, false
		}
		pos += 1 + l
	}
	if pos+10 > len(p) {
		return 0, 0, nil, false
	}
	rtype = binary.BigEndian.Uint16(p[pos:])
	rdlen := int(binary.BigEndian.Uint16(p[pos+8:]))
	pos += 10
	if pos+rdlen > len(p) {
		return 0, 0, nil, false
	}
	return pos + rdlen, rtype, p[pos : pos+rdlen], true
}

// inZone returns the labels left of the apex (nil at the apex) and whether
// the name is in the zone at all.
func (z zone) inZone(name string) ([]string, bool) {
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	if name == z.domain {
		return nil, true
	}
	if !strings.HasSuffix(name, "."+z.domain) {
		return nil, false
	}
	return strings.Split(strings.TrimSuffix(name, "."+z.domain), "."), true
}

func (z zone) isNS(name string) bool {
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	for _, n := range z.ns {
		if n == name {
			return true
		}
	}
	return false
}

// handleDNS answers one query from src and reports a beacon if the name
// carries one. transport is "udp" or "tcp".
func (r *receiver) handleDNS(p []byte, src, transport string) []byte {
	if len(p) < 12 || p[2]&0x80 != 0 { // ignore responses
		return nil
	}
	q, ok := parseQuestion(p)
	if !ok {
		return dnsHeaderOnly(p, rcodeFormat)
	}
	if opcode := (p[2] >> 3) & 0x0F; opcode != 0 {
		return r.dnsReply(p, q, rcodeNotImp, nil, nil)
	}
	below, ok := r.zone.inZone(q.name())
	if !ok {
		return r.dnsReply(p, q, rcodeRefuse, nil, nil)
	}

	if tok := r.verify.find(below...); tok != "" {
		typ, known := dnsTypes[q.qtype]
		if !known {
			typ = "TYPE" + strconv.Itoa(int(q.qtype))
		}
		d := sdk.EventDetails{
			{Key: "query_name", Value: decoy.Sanitize(strings.ToLower(q.name()), 256)},
			{Key: "query_type", Value: typ},
			{Key: "transport", Value: transport},
			{Key: "resolver", Value: src},
		}
		if cs := clientSubnet(p, q.end); cs != "" {
			d = append(d, sdk.EventDetail{Key: "client_subnet", Value: cs})
		}
		r.report(tok, "dns", src, d)
	}

	name := q.name()
	var answers, authority [][]byte
	switch {
	case below == nil && q.qtype == typeSOA:
		answers = append(answers, r.soaRR())
	case below == nil && q.qtype == typeNS:
		for _, n := range r.zone.ns {
			answers = append(answers, rr(r.zone.domain, typeNS, encodeName(n)))
		}
	case q.qtype == typeA && r.zone.ipv4 != nil: // apex, name servers and every name below
		answers = append(answers, rr(name, typeA, r.zone.ipv4.To4()))
	}
	if len(answers) == 0 {
		authority = append(authority, r.soaRR()) // NODATA, negative-cached for dnsTTL
	}
	return r.dnsReply(p, q, rcodeOK, answers, authority)
}

func (r *receiver) soaRR() []byte {
	mname := r.zone.domain
	if len(r.zone.ns) > 0 {
		mname = r.zone.ns[0]
	}
	rdata := append(encodeName(mname), encodeName("hostmaster."+r.zone.domain)...)
	var nums [20]byte
	binary.BigEndian.PutUint32(nums[0:], 1)       // serial
	binary.BigEndian.PutUint32(nums[4:], 3600)    // refresh
	binary.BigEndian.PutUint32(nums[8:], 600)     // retry
	binary.BigEndian.PutUint32(nums[12:], 86400)  // expire
	binary.BigEndian.PutUint32(nums[16:], dnsTTL) // negative TTL
	return rr(r.zone.domain, typeSOA, append(rdata, nums[:]...))
}

// dnsReply builds an authoritative response echoing the question exactly as
// sent (resolvers check the 0x20 case pattern).
func (r *receiver) dnsReply(p []byte, q question, rcode byte, answers, authority [][]byte) []byte {
	resp := make([]byte, q.end, q.end+128)
	copy(resp, p[:q.end])
	resp[2] = 0x80 | (p[2] & 0x79) // QR, opcode and RD copied
	if rcode != rcodeRefuse && rcode != rcodeNotImp {
		resp[2] |= 0x04 // AA
	}
	resp[3] = rcode
	binary.BigEndian.PutUint16(resp[4:], 1)
	binary.BigEndian.PutUint16(resp[6:], uint16(len(answers)))
	binary.BigEndian.PutUint16(resp[8:], uint16(len(authority)))
	binary.BigEndian.PutUint16(resp[10:], 0)
	for _, a := range answers {
		resp = append(resp, a...)
	}
	for _, a := range authority {
		resp = append(resp, a...)
	}
	return resp
}

// dnsHeaderOnly answers an unparseable query with just a header.
func dnsHeaderOnly(p []byte, rcode byte) []byte {
	resp := make([]byte, 12)
	copy(resp, p[:12])
	resp[2] = 0x80 | (p[2] & 0x79)
	resp[3] = rcode
	for i := 4; i < 12; i++ {
		resp[i] = 0
	}
	return resp
}

func rr(name string, rtype uint16, rdata []byte) []byte {
	out := encodeName(name)
	var hdr [10]byte
	binary.BigEndian.PutUint16(hdr[0:], rtype)
	binary.BigEndian.PutUint16(hdr[2:], classIN)
	binary.BigEndian.PutUint32(hdr[4:], dnsTTL)
	binary.BigEndian.PutUint16(hdr[8:], uint16(len(rdata)))
	out = append(out, hdr[:]...)
	return append(out, rdata...)
}

func encodeName(name string) []byte {
	var out []byte
	for _, l := range strings.Split(strings.TrimSuffix(name, "."), ".") {
		if l == "" {
			continue
		}
		if len(l) > 63 {
			l = l[:63]
		}
		out = append(out, byte(len(l)))
		out = append(out, l...)
	}
	return append(out, 0)
}

func (r *receiver) serveDNSUDP(ctx context.Context, pc net.PacketConn) {
	defer pc.Close()
	go func() {
		<-ctx.Done()
		pc.Close()
	}()
	buf := make([]byte, 4096)
	for {
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			continue
		}
		src := decoy.RemoteIP(addr)
		if ok, _ := r.replies.Allow(src); !ok {
			continue // spoofed floods can't turn the receiver into a reflector
		}
		if reply := r.handleDNS(buf[:n], src, "udp"); reply != nil {
			pc.WriteTo(reply, addr)
		}
	}
}

// serveDNSTCP handles one TCP connection: length-prefixed queries, a few per
// connection.
func (r *receiver) serveDNSTCP(conn net.Conn) {
	defer conn.Close()
	src := decoy.RemoteIP(conn.RemoteAddr())
	for i := 0; i < 8; i++ {
		conn.SetDeadline(time.Now().Add(10 * time.Second))
		var l [2]byte
		if _, err := io.ReadFull(conn, l[:]); err != nil {
			return
		}
		n := int(binary.BigEndian.Uint16(l[:]))
		if n < 12 || n > maxTCPQuery {
			return
		}
		msg := make([]byte, n)
		if _, err := io.ReadFull(conn, msg); err != nil {
			return
		}
		reply := r.handleDNS(msg, src, "tcp")
		if reply == nil {
			return
		}
		out := make([]byte, 2, 2+len(reply))
		binary.BigEndian.PutUint16(out, uint16(len(reply)))
		if _, err := conn.Write(append(out, reply...)); err != nil {
			return
		}
	}
}
