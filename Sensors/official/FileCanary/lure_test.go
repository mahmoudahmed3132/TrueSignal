package main

import (
	"regexp"
	"testing"
)

// The fake AWS key ID must look real (AKIA + 16 base32 characters), or it
// gives away the lure and the honeytoken next to it.
func TestAWSKeyIDLooksReal(t *testing.T) {
	re := regexp.MustCompile(`AWS_ACCESS_KEY_ID=(AKIA[A-Z2-7]{16})\n`)
	for i := 0; i < 50; i++ {
		content := string(lureContent("/srv/app/.env", honeytoken{}))
		if !re.MatchString(content) {
			t.Fatalf("key ID not AKIA+base32:\n%s", content)
		}
	}
}
