package main

import "bytes"

// CredSSP (MS-CSSP) carries SPNEGO/NTLM inside a DER TSRequest over TLS. The
// decoy only needs to: pull the NTLM message out of an inbound TSRequest, and
// wrap our NTLM challenge in an outbound TSRequest. For the inbound direction
// we locate the NTLMSSP signature directly rather than fully walking SPNEGO,
// which is robust across the ways clients frame it.

// SPNEGO and NTLM-mechanism OIDs (DER TLV bytes).
var (
	spnegoOID = []byte{0x06, 0x06, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02}
	ntlmOID   = []byte{0x06, 0x0a, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a}
)

// ctx wraps inner bytes in a DER context tag [n] (constructed).
func ctx(n byte, inner []byte) []byte { return berTLV(0xA0+n, inner) }

// credsspMessage is what we recovered from an inbound TSRequest.
type credsspMessage struct {
	version  int
	ntlm     []byte // NTLM message starting at the NTLMSSP signature
	ntlmType uint32
	spnego   bool // the NTLM token was framed in SPNEGO
}

// parseTSRequest reads the CredSSP version and locates the NTLM message.
func parseTSRequest(data []byte) (credsspMessage, bool) {
	var m credsspMessage
	// version lives in TSRequest [0] INTEGER; a small best-effort read.
	r := &berReader{buf: data}
	if tag, body, ok := r.readTLV(); ok && tag == tagSequence {
		s := &berReader{buf: body}
		if t, v, ok := s.readTLV(); ok && t == 0xA0 { // [0] version
			iv := &berReader{buf: v}
			if it, ib, ok := iv.readTLV(); ok && it == tagInteger && len(ib) > 0 {
				m.version = int(ib[len(ib)-1])
			}
		}
	}

	idx := bytes.Index(data, ntlmSignature)
	if idx < 0 || idx+12 > len(data) {
		return m, false
	}
	m.ntlm = data[idx:]
	m.ntlmType = uint32(m.ntlm[8]) | uint32(m.ntlm[9])<<8 | uint32(m.ntlm[10])<<16 | uint32(m.ntlm[11])<<24
	m.spnego = bytes.Contains(data[:idx], spnegoOID)
	return m, true
}

// buildChallengeTSRequest wraps an NTLM Type 2 in a TSRequest, matching the
// client's framing (SPNEGO NegTokenResp if the client used SPNEGO, else a raw
// NTLM token).
func buildChallengeTSRequest(version int, ntlmType2 []byte, spnego bool) []byte {
	token := ntlmType2
	if spnego {
		// NegTokenResp [1] { negState [0] accept-incomplete(1), supportedMech
		// [1] NTLM-OID, responseToken [2] OCTET STRING(Type2) }
		negState := ctx(0, berTLV(tagEnumerated, []byte{0x01}))
		supported := ctx(1, ntlmOID)
		respToken := ctx(2, berTLV(tagOctetStr, ntlmType2))
		token = ctx(1, berTLV(tagSequence, concat(negState, supported, respToken)))
	}
	// negoTokens [1] SEQUENCE OF SEQUENCE { negoToken [0] OCTET STRING }
	negoData := berTLV(tagSequence, berTLV(tagSequence, ctx(0, berTLV(tagOctetStr, token))))
	negoTokens := ctx(1, negoData)
	if version <= 0 {
		version = 6
	}
	ver := ctx(0, berInt(tagInteger, version))
	return berTLV(tagSequence, concat(ver, negoTokens))
}

// buildErrorTSRequest returns a TSRequest carrying an NTSTATUS errorCode, used
// to tell the client authentication failed (CredSSP version >= 3).
func buildErrorTSRequest(version int, ntStatus uint32) []byte {
	if version < 3 {
		version = 6
	}
	ver := ctx(0, berInt(tagInteger, version))
	// errorCode [4] INTEGER (unsigned NTSTATUS, keep it positive).
	ec := []byte{byte(ntStatus >> 24), byte(ntStatus >> 16), byte(ntStatus >> 8), byte(ntStatus)}
	errCode := ctx(4, berTLV(tagInteger, append([]byte{0x00}, ec...)))
	return berTLV(tagSequence, concat(ver, errCode))
}
