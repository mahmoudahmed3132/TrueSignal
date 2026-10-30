package beacon

import (
	"strings"
	"testing"

	"github.com/truesignal/hub/internal/models"
)

// The same vector is in Sensors/official/TokenReceiver: the receiver verifies
// what the Hub generates.
func TestTokenVector(t *testing.T) {
	random := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}
	if got := makeToken("truesignal-test-key", random); got != "aaaqeayeaudaocaj4jyx76cl" {
		t.Fatalf("token = %s", got)
	}
}

func TestRenderIsDeterministicAndUsesToken(t *testing.T) {
	for _, typ := range []string{TypeDNS, TypeWebBug, TypeKubeconfig} {
		b := models.Beacon{Token: "aaaqeayeaudaocaj4jyx76cl", Type: typ, Name: "Finance share / Q3", Domain: "t.example.com"}
		a1, a2 := Render(b), Render(b)
		if a1 != a2 {
			t.Errorf("%s: not deterministic", typ)
		}
		if !strings.Contains(a1.Content, b.Token) || !strings.Contains(a1.Value, b.Token) {
			t.Errorf("%s: token missing: %+v", typ, a1)
		}
		if strings.ContainsAny(a1.Filename, "/ \"") {
			t.Errorf("%s: unsafe filename %q", typ, a1.Filename)
		}
	}
	k := Render(models.Beacon{Token: "aaaqeayeaudaocaj4jyx76cl", Type: TypeKubeconfig, Name: "EKS prod", Domain: "t.example.com"})
	if !strings.Contains(k.Content, "server: https://aaaqeayeaudaocaj4jyx76cl.t.example.com:6443") ||
		strings.Contains(k.Content, "certificate-authority-data") || k.Filename != "kubeconfig-eks-prod.yaml" {
		t.Errorf("kubeconfig:\n%s", k.Content)
	}
	w := Render(models.Beacon{Token: "aaaqeayeaudaocaj4jyx76cl", Type: TypeWebBug, Name: "x", Domain: "t.example.com"})
	if w.Value != "http://t.example.com/static/aaaqeayeaudaocaj4jyx76cl.gif" {
		t.Errorf("web bug url = %s", w.Value)
	}
}

// The planted content must not reveal the product or the operator's note.
func TestArtifactsCarryNoProductOrPlantingNote(t *testing.T) {
	for _, typ := range []string{TypeDNS, TypeWebBug, TypeKubeconfig} {
		b := models.Beacon{Token: "aaaqeayeaudaocaj4jyx76cl", Type: typ, Name: "jump-01 finance share", Domain: "t.example.com"}
		c := strings.ToLower(Render(b).Content)
		for _, leak := range []string{"truesignal", "beacon", "jump-01", "finance"} {
			if strings.Contains(c, leak) {
				t.Errorf("%s artifact contains %q:\n%s", typ, leak, c)
			}
		}
	}
	if w := Render(models.Beacon{Token: "aaaqeayeaudaocaj4jyx76cl", Type: TypeWebBug, Domain: "t.example.com"}); !strings.HasPrefix(w.Content, "<img ") {
		t.Errorf("web bug content = %q", w.Content)
	}
}
