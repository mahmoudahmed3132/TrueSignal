package signing

import (
	"os"
	"strings"
	"testing"

	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/testing/ca"
	"github.com/sigstore/sigstore-go/pkg/verify"
)

const testIssuer = "https://token.actions.githubusercontent.com"

func virtual(t *testing.T) (*ca.VirtualSigstore, *Verifier) {
	t.Helper()
	vs, err := ca.NewVirtualSigstore()
	if err != nil {
		t.Fatal(err)
	}
	v, err := newVerifier(vs, DefaultSignerRepo, testIssuer, false)
	if err != nil {
		t.Fatal(err)
	}
	return vs, v
}

func TestIdentityPinsRepoWorkflowAndTag(t *testing.T) {
	_, v := virtual(t)
	want := "https://github.com/mahmoudahmed3132/TrueSignal/.github/workflows/publish-sensor-registry.yml@refs/tags/sensor/tcp-tarpit/v2.0.3"
	if got := v.Identity("tcp-tarpit", "2.0.3"); got != want {
		t.Fatalf("identity %s", got)
	}
}

func TestVerifyManifest(t *testing.T) {
	vs, v := virtual(t)
	manifest := []byte(`{"id":"ts-sensor-tcp-tarpit","version":"2.0.3"}`)
	good, err := vs.Sign(v.Identity("tcp-tarpit", "2.0.3"), testIssuer, manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := v.verifyEntity(good, "tcp-tarpit", "2.0.3", manifest); err != nil {
		t.Fatalf("valid signature rejected: %v", err)
	}

	cases := map[string]func() error{
		"tampered manifest": func() error {
			return v.verifyEntity(good, "tcp-tarpit", "2.0.3", []byte(`{"id":"ts-sensor-tcp-tarpit","version":"2.0.3","x":1}`))
		},
		"replayed under another version": func() error {
			return v.verifyEntity(good, "tcp-tarpit", "2.0.4", manifest)
		},
		"replayed under another sensor": func() error {
			return v.verifyEntity(good, "web-router-decoy", "2.0.3", manifest)
		},
		"signed by another repository": func() error {
			e, _ := vs.Sign(strings.Replace(v.Identity("tcp-tarpit", "2.0.3"), DefaultSignerRepo, "attacker/TrueSignal", 1), testIssuer, manifest)
			return v.verifyEntity(e, "tcp-tarpit", "2.0.3", manifest)
		},
		"signed by another workflow": func() error {
			e, _ := vs.Sign(strings.Replace(v.Identity("tcp-tarpit", "2.0.3"), "publish-sensor-registry.yml", "test.yml", 1), testIssuer, manifest)
			return v.verifyEntity(e, "tcp-tarpit", "2.0.3", manifest)
		},
		"signed from a branch, not the tag": func() error {
			e, _ := vs.Sign(strings.Replace(v.Identity("tcp-tarpit", "2.0.3"), "refs/tags/sensor/tcp-tarpit/v2.0.3", "refs/heads/main", 1), testIssuer, manifest)
			return v.verifyEntity(e, "tcp-tarpit", "2.0.3", manifest)
		},
		"other OIDC issuer": func() error {
			e, _ := vs.Sign(v.Identity("tcp-tarpit", "2.0.3"), "https://accounts.google.com", manifest)
			return v.verifyEntity(e, "tcp-tarpit", "2.0.3", manifest)
		},
		"untrusted CA": func() error {
			other, _ := ca.NewVirtualSigstore()
			e, _ := other.Sign(v.Identity("tcp-tarpit", "2.0.3"), testIssuer, manifest)
			return v.verifyEntity(e, "tcp-tarpit", "2.0.3", manifest)
		},
		"path traversal in name": func() error {
			return v.verifyEntity(good, "../tcp-tarpit", "2.0.3", manifest)
		},
	}
	for name, f := range cases {
		if err := f(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestVerifyManifestRejectsMissingOrGarbageBundle(t *testing.T) {
	_, v := virtual(t)
	if err := v.VerifyManifest("tcp-tarpit", "2.0.3", []byte("{}"), nil); err == nil || !strings.Contains(err.Error(), "not signed") {
		t.Fatalf("missing bundle: %v", err)
	}
	if err := v.VerifyManifest("tcp-tarpit", "2.0.3", []byte("{}"), []byte(`{"mediaType":"nope"}`)); err == nil {
		t.Fatal("garbage bundle accepted")
	}
}

// The embedded public-good root and the production verifier options accept a
// real Sigstore public-good signature (sigstore-js release provenance, from
// sigstore-go's test data), including its SCT, Rekor entry and timestamp.
func TestEmbeddedPublicGoodRootVerifiesRealBundle(t *testing.T) {
	tm, err := TrustedRoot("")
	if err != nil {
		t.Fatal(err)
	}
	v, err := New(tm, DefaultSignerRepo)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile("testdata/publicgood-provenance.sigstore.json")
	if err != nil {
		t.Fatal(err)
	}
	var b bundle.Bundle
	if err := b.UnmarshalJSON(raw); err != nil {
		t.Fatal(err)
	}
	id, _ := verify.NewShortCertificateIdentity(GitHubOIDCIssuer, "", "https://github.com/sigstore/sigstore-js/.github/workflows/release.yml@refs/heads/main", "")
	if _, err := v.v.Verify(&b, verify.NewPolicy(verify.WithoutArtifactUnsafe(), verify.WithCertificateIdentity(id))); err != nil {
		t.Fatalf("real public-good bundle rejected: %v", err)
	}
	// Our pinned identity does not match someone else's valid signature.
	other, _ := verify.NewShortCertificateIdentity(GitHubOIDCIssuer, "", v.Identity("tcp-tarpit", "2.0.3"), "")
	if _, err := v.v.Verify(&b, verify.NewPolicy(verify.WithoutArtifactUnsafe(), verify.WithCertificateIdentity(other))); err == nil {
		t.Fatal("foreign signature accepted under our identity")
	}
}

func TestNewRejectsBadRepo(t *testing.T) {
	tm, _ := TrustedRoot("")
	for _, r := range []string{"", "noslash", "a/b/c", "a/b@refs"} {
		if _, err := New(tm, r); err == nil {
			t.Errorf("%q accepted", r)
		}
	}
}
