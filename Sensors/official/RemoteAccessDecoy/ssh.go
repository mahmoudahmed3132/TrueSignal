package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"net"

	sdk "github.com/truesignal/sdk-go"
	"github.com/truesignal/sdk-go/decoy"
	"golang.org/x/crypto/ssh"
)

// sshServer holds the host key and version string shared by all connections.
type sshServer struct {
	signer  ssh.Signer
	version string
}

func newSSHServer(nodeKey, version string) (*sshServer, error) {
	seed := sha256.Sum256([]byte("truesignal-ssh-hostkey:" + nodeKey))
	signer, err := ssh.NewSignerFromKey(ed25519.NewKeyFromSeed(seed[:]))
	if err != nil {
		return nil, err
	}
	return &sshServer{signer: signer, version: version}, nil
}

var errDenied = errors.New("permission denied")

// serveSSH runs the SSH handshake and records every authentication attempt:
// passwords (through the capture policy), keyboard-interactive answers, and
// public keys offered (type and SHA256 fingerprint, the identity of a stolen
// key). Every attempt is refused, so no channel is ever opened.
func (h *handler) serveSSH(conn net.Conn) {
	src := decoy.RemoteIP(conn.RemoteAddr())
	clientVersion := func(c ssh.ConnMetadata) sdk.EventDetails {
		return sdk.EventDetails{{Key: "client_version", Value: decoy.Sanitize(string(c.ClientVersion()), 128)}}
	}

	cfg := &ssh.ServerConfig{
		ServerVersion: h.ssh.version,
		MaxAuthTries:  maxAttempts,
		PasswordCallback: func(c ssh.ConnMetadata, pw []byte) (*ssh.Permissions, error) {
			p := string(pw)
			h.reportLogin(src, c.User(), "password", &p, clientVersion(c))
			return nil, errDenied
		},
		KeyboardInteractiveCallback: func(c ssh.ConnMetadata, challenge ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
			answers, err := challenge("", "", []string{"Password: "}, []bool{false})
			if err != nil || len(answers) != 1 {
				return nil, errDenied
			}
			h.reportLogin(src, c.User(), "keyboard-interactive", &answers[0], clientVersion(c))
			return nil, errDenied
		},
		PublicKeyCallback: func(c ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			extra := append(clientVersion(c),
				sdk.EventDetail{Key: "key_type", Value: key.Type()},
				sdk.EventDetail{Key: "key_fingerprint", Value: ssh.FingerprintSHA256(key)})
			h.reportLogin(src, c.User(), "publickey", nil, extra)
			return nil, errDenied
		},
	}
	cfg.AddHostKey(h.ssh.signer)

	// NewServerConn returns once authentication fails for good (or the client
	// gives up); it never succeeds because every callback denies.
	if sc, chans, reqs, err := ssh.NewServerConn(conn, cfg); err == nil {
		go ssh.DiscardRequests(reqs)
		for ch := range chans {
			ch.Reject(ssh.Prohibited, "denied")
		}
		sc.Close()
	}
}
