package main

import (
	"bytes"
	"net"
	"strings"

	sdk "github.com/truesignal/sdk-go"
)

// NTLM binds against the LDAP decoy. AD accepts NTLM two ways:
//
//   - Sicily (MS-ADTS 5.1.1.1.3), used by ldap3-based tools such as
//     BloodHound.py and ldapdomaindump: [9] package discovery, [10] NTLM
//     NEGOTIATE, [11] NTLM AUTHENTICATE. The server returns the package list
//     and the CHALLENGE in the bindResponse matchedDN with resultCode success.
//   - SASL GSS-SPNEGO, used by impacket (raw NTLMSSP) and Windows/.NET
//     clients such as SharpHound (SPNEGO-framed): the CHALLENGE goes back in
//     serverSaslCreds with saslBindInProgress.
//
// Either way the AUTHENTICATE is answered invalidCredentials with the AD
// "data 52e" diagnostic, so access is never granted.

// handleNTLMBind runs one step of a Sicily or SASL NTLM bind.
func (h *ldapHandler) handleNTLMBind(conn net.Conn, msgID []byte, res bindResult) bool {
	if h.ntlmMode == "off" {
		h.writeBindResponse(conn, msgID, resultAuthMethodNotSupp, nil, "", nil)
		return true
	}

	switch res.authTag {
	case authSicilyDisc:
		h.writeBindResponse(conn, msgID, resultSuccess, []byte("NTLM"), "", nil)
		return true
	case authSicilyNeg, authSicilyResp:
		return h.ntlmStep(conn, msgID, res.authVal, "sicily_ntlm", false)
	}

	// SaslCredentials: mechanism LDAPString, credentials OCTET STRING OPTIONAL.
	r := &berReader{buf: res.authVal}
	_, mech, ok := r.readTLV()
	if !ok {
		return false
	}
	var creds []byte
	if !r.done() {
		if _, c, ok := r.readTLV(); ok {
			creds = c
		}
	}
	mechanism := strings.ToUpper(sanitizeUTF8(string(mech)))
	if mechanism != "GSS-SPNEGO" && mechanism != "NTLM" {
		// GSSAPI (Kerberos), DIGEST-MD5, EXTERNAL: nothing to capture without
		// a KDC; record the attempt and refuse the mechanism.
		h.ts.ReportEventSeverity("medium", h.proto+"_query", remoteIP(conn), h.target(),
			sdk.EventDetails{
				{Key: "protocol", Value: h.proto},
				{Key: "dst_port", Value: h.port},
				{Key: "sasl_mechanism", Value: truncate(mechanism, 64)},
			})
		h.writeBindResponse(conn, msgID, resultAuthMethodNotSupp, nil, "", nil)
		return true
	}
	return h.ntlmStep(conn, msgID, creds, "sasl_ntlm", true)
}

// ntlmStep handles a NEGOTIATE (reply with a CHALLENGE) or an AUTHENTICATE
// (record the identity, refuse it).
func (h *ldapHandler) ntlmStep(conn net.Conn, msgID, token []byte, auth string, sasl bool) bool {
	msg, msgType, spnego, ok := findNTLM(token)
	if sasl && spnego {
		h.spnego = true
	}

	if !ok {
		// A SPNEGO NegTokenInit that offers NTLM but carries an optimistic
		// Kerberos token: select NTLM so the client retries with it.
		if sasl && h.spnego && bytes.Contains(token, ntlmOID) {
			h.writeBindResponse(conn, msgID, resultSaslBindInProgress, nil, "", spnegoNTLMResp(nil))
			return true
		}
		h.writeBindResponse(conn, msgID, resultInvalidCredentials, nil, adInvalidCreds, nil)
		return true
	}

	switch msgType {
	case 1:
		h.challenge = randomChallenge()
		type2 := buildNTLMChallenge(h.challenge, h.persona)
		switch {
		case !sasl:
			h.writeBindResponse(conn, msgID, resultSuccess, type2, "", nil)
		case h.spnego:
			h.writeBindResponse(conn, msgID, resultSaslBindInProgress, nil, "", spnegoNTLMResp(type2))
		default:
			h.writeBindResponse(conn, msgID, resultSaslBindInProgress, nil, "", type2)
		}
		return true
	case 3:
		if h.challenge != nil {
			if c, ok := parseNTLMType3(msg); ok {
				h.reportNTLM(conn, c, auth)
			}
		}
		h.challenge = nil
		h.writeBindResponse(conn, msgID, resultInvalidCredentials, nil, adInvalidCreds, nil)
		return true
	default:
		h.writeBindResponse(conn, msgID, resultInvalidCredentials, nil, adInvalidCreds, nil)
		return true
	}
}

func (h *ldapHandler) reportNTLM(conn net.Conn, c ntlm3, auth string) {
	srcIP := remoteIP(conn)
	if c.user == "" {
		// Anonymous NTLM (null session): enumeration, not a login.
		h.ts.ReportEventSeverity("medium", h.proto+"_query", srcIP, h.target(),
			sdk.EventDetails{
				{Key: "protocol", Value: h.proto},
				{Key: "dst_port", Value: h.port},
				{Key: "auth", Value: auth + "_anonymous"},
				{Key: "workstation", Value: c.workstation},
			})
		return
	}
	h.ts.ReportEventSeverity("critical", h.proto+"_login", srcIP, h.target(),
		ntlmLoginDetails(h.proto, h.port, c, h.challenge, h.ntlmMode, auth))
}
