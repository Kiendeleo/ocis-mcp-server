package secretbox

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestParseAndRoundTrip(t *testing.T) {
	raw := bytes.Repeat([]byte{0x11}, 32)
	hexKey := hex.EncodeToString(raw)

	key, err := ParseKey(hexKey)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(key, raw) {
		t.Fatalf("parsed key mismatch")
	}

	plain := []byte("ocis-refresh-token-example")
	ct, err := Seal(key, plain)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Open(key, ct)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatalf("got %q want %q", got, plain)
	}

	ct[len(ct)-1] ^= 0xff
	if _, err := Open(key, ct); err == nil {
		t.Fatal("tampered blob should fail")
	}
}

func TestDeriveIsolatesUses(t *testing.T) {
	master := bytes.Repeat([]byte{0x22}, 32)
	a := Derive(master, "jwt")
	b := Derive(master, "cookie")
	if bytes.Equal(a, b) {
		t.Fatal("derived keys must differ by info label")
	}
	if bytes.Equal(a, master) {
		t.Fatal("derived key must not equal master")
	}
}

func TestParseKeyRejectsShort(t *testing.T) {
	if _, err := ParseKey("deadbeef"); err == nil {
		t.Fatal("expected error")
	}
}
