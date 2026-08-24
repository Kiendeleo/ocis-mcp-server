package config

import (
	"os"
	"testing"
)

func TestLoadOAuthMode(t *testing.T) {
	clearEnv()
	_ = os.Setenv("OCIS_MCP_OCIS_URL", "https://ocis.example.com")
	_ = os.Setenv("OCIS_MCP_AUTH_MODE", "oauth")
	_ = os.Setenv("OCIS_MCP_TRANSPORT", "http")
	_ = os.Setenv("OCIS_MCP_HTTP_ADDR", "0.0.0.0:8090")
	_ = os.Setenv("OCIS_MCP_PUBLIC_URL", "https://mcp.example.com")
	_ = os.Setenv("OCIS_MCP_OIDC_CLIENT_ID", "ocis")
	_ = os.Setenv("OCIS_MCP_GRANT_KEY", "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("oauth mode should not need HTTP_SECRET: %v", err)
	}
	if cfg.AuthMode != "oauth" {
		t.Fatalf("AuthMode=%q", cfg.AuthMode)
	}
	if !cfg.HTTPAuthEnabled() {
		t.Fatal("oauth mode must report HTTPAuthEnabled")
	}
}

func TestLoadOAuthModeMissingKey(t *testing.T) {
	clearEnv()
	_ = os.Setenv("OCIS_MCP_OCIS_URL", "https://ocis.example.com")
	_ = os.Setenv("OCIS_MCP_AUTH_MODE", "oauth")
	_ = os.Setenv("OCIS_MCP_TRANSPORT", "http")
	_ = os.Setenv("OCIS_MCP_PUBLIC_URL", "https://mcp.example.com")
	_ = os.Setenv("OCIS_MCP_OIDC_CLIENT_ID", "ocis")
	if _, err := Load(); err == nil {
		t.Fatal("expected error without GRANT_KEY")
	}
}

func TestLoadOAuthModeBadKey(t *testing.T) {
	clearEnv()
	_ = os.Setenv("OCIS_MCP_OCIS_URL", "https://ocis.example.com")
	_ = os.Setenv("OCIS_MCP_AUTH_MODE", "oauth")
	_ = os.Setenv("OCIS_MCP_TRANSPORT", "http")
	_ = os.Setenv("OCIS_MCP_PUBLIC_URL", "https://mcp.example.com")
	_ = os.Setenv("OCIS_MCP_OIDC_CLIENT_ID", "ocis")
	_ = os.Setenv("OCIS_MCP_GRANT_KEY", "tooshort")
	if _, err := Load(); err == nil {
		t.Fatal("expected error for short GRANT_KEY")
	}
}

func TestLoadOAuthRequiresHTTP(t *testing.T) {
	clearEnv()
	_ = os.Setenv("OCIS_MCP_OCIS_URL", "https://ocis.example.com")
	_ = os.Setenv("OCIS_MCP_AUTH_MODE", "oauth")
	_ = os.Setenv("OCIS_MCP_PUBLIC_URL", "https://mcp.example.com")
	_ = os.Setenv("OCIS_MCP_OIDC_CLIENT_ID", "ocis")
	_ = os.Setenv("OCIS_MCP_GRANT_KEY", "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")
	if _, err := Load(); err == nil {
		t.Fatal("oauth + stdio should fail")
	}
}
