// Package secretbox encrypts small blobs (tokens, session payloads) at rest.
//
// Why this exists:
//   We store oCIS access/refresh tokens and consent-session JSON in SQLite.
//   Those values must be unreadable if someone copies the database file.
//   AES-256-GCM is the standard authenticated-encryption construction:
//   it both hides the data (confidentiality) and detects tampering (integrity).
//
// The 32-byte key is derived from OCIS_MCP_GRANT_KEY via HKDF so we can
// mint independent keys for JWT signing, cookies, and column encryption
// from a single operator secret.
package secretbox

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"strings"

	"golang.org/x/crypto/hkdf"
)

const keySize = 32 // AES-256

// ParseKey accepts a GRANT_KEY as hex (64 chars) or standard/raw base64.
// A 32-byte raw value is also accepted if the env var is already binary-safe
// (unusual in compose files).
func ParseKey(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, fmt.Errorf("empty key")
	}
	if b, err := hex.DecodeString(s); err == nil && len(b) == keySize {
		return b, nil
	}
	if b, err := base64.StdEncoding.DecodeString(s); err == nil && len(b) == keySize {
		return b, nil
	}
	if b, err := base64.RawStdEncoding.DecodeString(s); err == nil && len(b) == keySize {
		return b, nil
	}
	return nil, fmt.Errorf("GRANT_KEY must be 32 bytes (64 hex chars or base64)")
}

// Derive stretches master into a named 32-byte key. info must be a stable
// ASCII label such as "jwt", "cookie", or "columns" so each use is isolated.
func Derive(master []byte, info string) []byte {
	r := hkdf.New(sha256.New, master, nil, []byte(info))
	out := make([]byte, keySize)
	_, _ = io.ReadFull(r, out)
	return out
}

// Seal encrypts plaintext. The result is nonce||ciphertext (nonce is 12 bytes).
func Seal(key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("reading nonce: %w", err)
	}
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

// Open decrypts a blob produced by Seal. Tampered data returns an error.
func Open(key, blob []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	ns := gcm.NonceSize()
	if len(blob) < ns {
		return nil, fmt.Errorf("ciphertext too short")
	}
	return gcm.Open(nil, blob[:ns], blob[ns:], nil)
}
