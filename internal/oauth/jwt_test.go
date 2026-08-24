package oauth

import (
	"bytes"
	"testing"
	"time"
)

func TestSignAndParseAccess(t *testing.T) {
	key := bytes.Repeat([]byte{0x09}, 32)
	tok, err := SignAccess(key, "https://mcp.example", "https://mcp.example/mcp", "user-1", "grant-1", "client-1", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	c, err := ParseAccess(key, "https://mcp.example", "https://mcp.example/mcp", tok)
	if err != nil {
		t.Fatal(err)
	}
	if c.GrantID != "grant-1" || c.ClientID != "client-1" || c.Subject != "user-1" {
		t.Fatalf("%+v", c)
	}
	if _, err := ParseAccess(key, "https://mcp.example", "https://other/mcp", tok); err == nil {
		t.Fatal("wrong audience")
	}
	if _, err := ParseAccess(bytes.Repeat([]byte{0x08}, 32), "https://mcp.example", "https://mcp.example/mcp", tok); err == nil {
		t.Fatal("wrong key")
	}
}

func TestValidRedirectURI(t *testing.T) {
	ok := []string{
		"https://claude.ai/callback",
		"http://127.0.0.1:54321/cb",
		"http://localhost/cb",
	}
	bad := []string{
		"http://evil.example/cb",
		"javascript:alert(1)",
		"ftp://127.0.0.1/x",
		"https://ok.example/cb#frag",
		"",
	}
	for _, u := range ok {
		if !ValidRedirectURI(u) {
			t.Errorf("want ok %q", u)
		}
	}
	for _, u := range bad {
		if ValidRedirectURI(u) {
			t.Errorf("want reject %q", u)
		}
	}
}
