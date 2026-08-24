package oauth

import (
	"crypto/sha256"
	"encoding/base64"
	"testing"
)

func TestVerifyS256(t *testing.T) {
	v := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	sum := sha256.Sum256([]byte(v))
	ch := base64.RawURLEncoding.EncodeToString(sum[:])
	if !VerifyS256(v, ch) {
		t.Fatal("rfc7636 example should verify")
	}
	if VerifyS256(v, "nope") {
		t.Fatal("wrong challenge")
	}
}
