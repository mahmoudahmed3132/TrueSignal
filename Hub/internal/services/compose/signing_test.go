package composesvc_test

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/truesignal/hub/internal/catalog"
	composesvc "github.com/truesignal/hub/internal/services/compose"
)

// fakeVerifier accepts a bundle only if it equals "sig:" + the manifest bytes,
// standing in for a Sigstore signature over exactly those bytes.
type fakeVerifier struct{ calls []string }

func (f *fakeVerifier) VerifyManifest(name, version string, manifest, bundle []byte) error {
	f.calls = append(f.calls, name+"@"+version)
	if !bytes.Equal(bundle, append([]byte("sig:"), manifest...)) {
		return errors.New("bad signature")
	}
	return nil
}

var signedManifest = `{"id":"ts-sensor-test","version":"1.2.3","deployment":{"image_repository":"test","image_tag":"v1.2.3","image_digest":"` + testDigest + `"}}`

func registry(t *testing.T, bundles map[string]string) *httptest.Server {
	t.Helper()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/test-v1.2.3.json":
			w.Write([]byte(signedManifest))
		case strings.HasSuffix(r.URL.Path, ".sigstore.json"):
			if b, ok := bundles[r.URL.Path]; ok {
				w.Write([]byte(b))
				return
			}
			http.NotFound(w, r)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(ts.Close)
	return ts
}

func TestFetchSpecificManifestRequiresValidSignature(t *testing.T) {
	cases := map[string]struct {
		bundles map[string]string
		ok      bool
	}{
		"valid signature":          {map[string]string{"/test-v1.2.3.json.sigstore.json": "sig:" + signedManifest}, true},
		"unsigned":                 {nil, false},
		"signature of other bytes": {map[string]string{"/test-v1.2.3.json.sigstore.json": "sig:{}"}, false},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			ts := registry(t, c.bundles)
			store := &MockStore{RegistryURL: ts.URL}
			svc := composesvc.NewService(store, catalog.NewService(store, nil))
			fv := &fakeVerifier{}
			svc.SetManifestVerifier(fv)
			m, err := svc.FetchSpecificManifest("ts-sensor-test", "v1.2.3")
			if (err == nil) != c.ok {
				t.Fatalf("err = %v, want ok=%v", err, c.ok)
			}
			if c.ok && (m.Version != "1.2.3" || fv.calls[0] != "test@1.2.3") {
				t.Fatalf("manifest %+v calls %v", m, fv.calls)
			}
		})
	}
}

func TestUnsignedAllowedOnlyWithoutVerifier(t *testing.T) {
	ts := registry(t, nil)
	store := &MockStore{RegistryURL: ts.URL}
	svc := composesvc.NewService(store, catalog.NewService(store, nil))
	if _, err := svc.FetchSpecificManifest("ts-sensor-test", "1.2.3"); err != nil {
		t.Fatalf("no verifier (TS_ALLOW_UNSIGNED_MANIFESTS) should accept: %v", err)
	}
}

func TestManifestIdentityMismatchRejected(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// A different sensor's manifest served under this sensor's path.
		w.Write([]byte(strings.Replace(signedManifest, "ts-sensor-test", "ts-sensor-other", 1)))
	}))
	defer ts.Close()
	store := &MockStore{RegistryURL: ts.URL}
	svc := composesvc.NewService(store, catalog.NewService(store, nil))
	if _, err := svc.FetchSpecificManifest("ts-sensor-test", "1.2.3"); err == nil || !strings.Contains(err.Error(), "identity mismatch") {
		t.Fatalf("swapped manifest: %v", err)
	}
}
