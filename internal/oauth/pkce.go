package oauth

import (
	"crypto/sha256"
	"encoding/base64"
	"crypto/subtle"
)

// VerifyS256 is RFC 7636: BASE64URL(SHA256(verifier)) == challenge.
func VerifyS256(verifier, challenge string) bool {
	sum := sha256.Sum256([]byte(verifier))
	got := base64.RawURLEncoding.EncodeToString(sum[:])
	if len(got) != len(challenge) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(got), []byte(challenge)) == 1
}
