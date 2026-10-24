package main

import (
	"strconv"
	"strings"
	"time"

	sdk "github.com/truesignal/sdk-go"
	"github.com/truesignal/sdk-go/decoy"
)

// SNMP v1/v2c/v3, enough to record who is probing and with what. The
// community string is a credential, so it goes through the capture policy.
// Requests with the configured community (TS_SNMP_COMMUNITY) get answers for
// the system group, so the decoy looks like a live device; any other community
// gets no reply, exactly like a real agent. v3 requests record the USM user
// name and get no reply (no v3 users exist).

const (
	tagInt      = 0x02
	tagOctets   = 0x04
	tagNull     = 0x05
	tagOID      = 0x06
	tagSeq      = 0x30
	tagTimeTick = 0x43

	pduGet      = 0xA0
	pduGetNext  = 0xA1
	pduResponse = 0xA2
	pduSet      = 0xA3
	pduGetBulk  = 0xA5

	noSuchObject = 0x80 // v2c exception
	v1NoSuchName = 2
)

var pduNames = map[byte]string{pduGet: "get", pduGetNext: "getnext", pduSet: "set", pduGetBulk: "getbulk", 0xA6: "inform", 0xA7: "trap"}

// tlv reads one BER element.
func tlv(b []byte, pos int) (tag byte, val []byte, next int, ok bool) {
	if pos+2 > len(b) {
		return 0, nil, 0, false
	}
	tag = b[pos]
	n := int(b[pos+1])
	pos += 2
	if n&0x80 != 0 {
		c := n & 0x7f
		if c == 0 || c > 3 || pos+c > len(b) {
			return 0, nil, 0, false
		}
		n = 0
		for i := 0; i < c; i++ {
			n = n<<8 | int(b[pos+i])
		}
		pos += c
	}
	if pos+n > len(b) {
		return 0, nil, 0, false
	}
	return tag, b[pos : pos+n], pos + n, true
}

func enc(tag byte, val []byte) []byte {
	n := len(val)
	switch {
	case n < 0x80:
		return append([]byte{tag, byte(n)}, val...)
	case n < 0x100:
		return append([]byte{tag, 0x81, byte(n)}, val...)
	default:
		return append([]byte{tag, 0x82, byte(n >> 8), byte(n)}, val...)
	}
}

func encInt(tag byte, v int64) []byte {
	var b []byte
	for {
		b = append([]byte{byte(v)}, b...)
		v >>= 8
		if (v == 0 && b[0]&0x80 == 0) || (v == -1 && b[0]&0x80 != 0) {
			break
		}
	}
	return enc(tag, b)
}

func decInt(b []byte) int64 {
	var v int64
	for i, c := range b {
		if i == 0 && c&0x80 != 0 {
			v = -1
		}
		v = v<<8 | int64(c)
	}
	return v
}

func oidString(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	parts := []string{strconv.Itoa(int(b[0]) / 40), strconv.Itoa(int(b[0]) % 40)}
	v := 0
	for _, c := range b[1:] {
		v = v<<7 | int(c&0x7f)
		if c&0x80 == 0 {
			parts = append(parts, strconv.Itoa(v))
			v = 0
		}
	}
	return strings.Join(parts, ".")
}

// system-group OIDs the decoy answers.
const (
	oidSysDescr  = "1.3.6.1.2.1.1.1.0"
	oidSysUpTime = "1.3.6.1.2.1.1.3.0"
	oidSysName   = "1.3.6.1.2.1.1.5.0"
)

type snmpRequest struct {
	version   int64
	community string
	user      string // v3 USM user
	pdu       byte
	requestID []byte // raw INTEGER value, echoed back
	oids      [][]byte
}

func parseSNMP(p []byte) (snmpRequest, bool) {
	var r snmpRequest
	tag, msg, _, ok := tlv(p, 0)
	if !ok || tag != tagSeq {
		return r, false
	}
	tag, ver, pos, ok := tlv(msg, 0)
	if !ok || tag != tagInt {
		return r, false
	}
	r.version = decInt(ver)
	if r.version == 3 {
		// msgGlobalData, then msgSecurityParameters: an OCTET STRING holding
		// the USM SEQUENCE {engineID, boots, time, userName, ...}.
		if _, _, pos, ok = tlv(msg, pos); !ok {
			return r, false
		}
		if tag, sec, _, ok := tlv(msg, pos); ok && tag == tagOctets {
			if tag, usm, _, ok := tlv(sec, 0); ok && tag == tagSeq {
				p := 0
				for i := 0; i < 4 && ok; i++ {
					var v []byte
					tag, v, p, ok = tlv(usm, p)
					if i == 3 && ok && tag == tagOctets {
						r.user = string(v)
					}
				}
			}
		}
		return r, true
	}
	tag, comm, pos, ok := tlv(msg, pos)
	if !ok || tag != tagOctets {
		return r, false
	}
	r.community = string(comm)
	tag, pdu, _, ok := tlv(msg, pos)
	if !ok {
		return r, false
	}
	r.pdu = tag
	_, reqID, pos, ok := tlv(pdu, 0)
	if !ok {
		return r, false
	}
	r.requestID = reqID
	_, _, pos, ok = tlv(pdu, pos) // error-status / non-repeaters
	if ok {
		_, _, pos, ok = tlv(pdu, pos) // error-index / max-repetitions
	}
	if !ok {
		return r, true
	}
	if _, vbl, _, ok := tlv(pdu, pos); ok {
		for vp := 0; vp < len(vbl) && len(r.oids) < 16; {
			_, vb, next, ok := tlv(vbl, vp)
			if !ok {
				break
			}
			if tag, oid, _, ok := tlv(vb, 0); ok && tag == tagOID {
				r.oids = append(r.oids, oid)
			}
			vp = next
		}
	}
	return r, true
}

func (h *handler) handleSNMP(p []byte, src string) []byte {
	r, ok := parseSNMP(p)
	if !ok {
		return nil
	}
	version := map[int64]string{0: "v1", 1: "v2c", 3: "v3"}[r.version]
	if version == "" {
		return nil
	}
	d := sdk.EventDetails{{Key: "snmp_version", Value: version}}
	severity := "medium"
	if r.version == 3 {
		d = append(d, sdk.EventDetail{Key: "username", Value: decoy.Sanitize(r.user, 64)})
		h.report(severity, "snmp_query", src, d)
		return nil
	}
	valid := r.community == h.community
	pdu := pduNames[r.pdu]
	if pdu == "" {
		pdu = "unknown"
	}
	if r.pdu == pduSet {
		severity = "high" // a write attempt against a "device"
	}
	var oids []string
	for _, o := range r.oids {
		oids = append(oids, oidString(o))
	}
	d = append(d,
		sdk.EventDetail{Key: "pdu", Value: pdu},
		sdk.EventDetail{Key: "community_valid", Value: valid},
		sdk.EventDetail{Key: "oids", Value: decoy.Sanitize(strings.Join(oids, ","), 512)})
	d = append(d, h.cap.Secret("community", r.community)...)
	if !h.report(severity, "snmp_query", src, d) || !valid || r.pdu == pduSet {
		return nil // wrong community: silence, like a real agent
	}
	return h.snmpResponse(r)
}

func (h *handler) snmpResponse(r snmpRequest) []byte {
	var vbs []byte
	errStatus, errIndex := int64(0), int64(0)
	for i, raw := range r.oids {
		oid := oidString(raw)
		if r.pdu == pduGetNext || r.pdu == pduGetBulk {
			// Walk the three answered objects in order.
			next := ""
			for _, cand := range []string{oidSysDescr, oidSysUpTime, oidSysName} {
				if oidLess(oid, cand) {
					next = cand
					break
				}
			}
			oid = next
		}
		var val []byte
		switch oid {
		case oidSysDescr:
			val = enc(tagOctets, []byte(h.persona.sysDescr))
		case oidSysUpTime:
			val = encInt(tagTimeTick, int64(time.Since(h.started)/(10*time.Millisecond))+8_640_000)
		case oidSysName:
			val = enc(tagOctets, []byte(h.persona.hostname))
		default:
			if r.version == 0 {
				errStatus, errIndex = v1NoSuchName, int64(i+1)
			}
			val = []byte{noSuchObject, 0}
		}
		oidBytes := raw
		if oid != "" && oid != oidString(raw) {
			oidBytes = encodeOID(oid)
		}
		vbs = append(vbs, enc(tagSeq, append(enc(tagOID, oidBytes), val...))...)
	}
	pdu := enc(pduResponse, concat(enc(tagInt, r.requestID), encInt(tagInt, errStatus), encInt(tagInt, errIndex), enc(tagSeq, vbs)))
	return enc(tagSeq, concat(encInt(tagInt, r.version), enc(tagOctets, []byte(r.community)), pdu))
}

// oidLess orders OIDs by numeric arc, so 1.3.6.1.2.1.1.2 < 1.3.6.1.2.1.1.10.
func oidLess(a, b string) bool {
	pa, pb := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < len(pa) && i < len(pb); i++ {
		x, _ := strconv.Atoi(pa[i])
		y, _ := strconv.Atoi(pb[i])
		if x != y {
			return x < y
		}
	}
	return len(pa) < len(pb)
}

func encodeOID(s string) []byte {
	var nums []int
	for _, p := range strings.Split(s, ".") {
		n := 0
		for _, c := range p {
			n = n*10 + int(c-'0')
		}
		nums = append(nums, n)
	}
	out := []byte{byte(nums[0]*40 + nums[1])}
	for _, n := range nums[2:] {
		var b []byte
		b = append(b, byte(n&0x7f))
		for n >>= 7; n > 0; n >>= 7 {
			b = append([]byte{byte(n&0x7f) | 0x80}, b...)
		}
		out = append(out, b...)
	}
	return out
}

func concat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}
