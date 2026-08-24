package config

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/owncloud/ocis-mcp-server/internal/secretbox"
)

// Config holds all configuration for the MCP server, loaded from environment variables.
type Config struct {
	// oCIS connection
	OcisURL string // OCIS_MCP_OCIS_URL

	// Authentication mode: "app-token", "oidc", or "oauth" (default: auto-detect)
	AuthMode string // OCIS_MCP_AUTH_MODE

	// App Token auth (preferred for local/stdio MCP)
	AppTokenUser  string // OCIS_MCP_APP_TOKEN_USER
	AppTokenValue string // OCIS_MCP_APP_TOKEN_VALUE

	// OIDC auth (static bearer) OR oauth-mode upstream client.
	// OCIS_MCP_OIDC_CLIENT_ID / SECRET are the same Authentik application
	// the oCIS container uses — share them from one compose env file.
	OidcIssuer       string // OCIS_MCP_OIDC_ISSUER (optional; discovered from oCIS)
	OidcClientID     string // OCIS_MCP_OIDC_CLIENT_ID
	OidcClientSecret string // OCIS_MCP_OIDC_CLIENT_SECRET
	OidcAccessToken  string // OCIS_MCP_OIDC_ACCESS_TOKEN

	// OAuth 2.1 (MCP as authorization server + oCIS login)
	PublicURL string // OCIS_MCP_PUBLIC_URL  e.g. https://mcp.example.com
	GrantDB   string // OCIS_MCP_GRANT_DB    sqlite path
	GrantKey  string // OCIS_MCP_GRANT_KEY   32-byte hex/base64

	// Education API (optional)
	EducationAccessToken string // OCIS_MCP_EDUCATION_ACCESS_TOKEN

	// Transport
	Transport string // OCIS_MCP_TRANSPORT ("stdio" | "http", default: "stdio")
	HTTPAddr  string // OCIS_MCP_HTTP_ADDR (default: "127.0.0.1:8090")

	// HTTPSecret is the shared secret required as `Authorization: Bearer <secret>` on the
	// HTTP transport's /mcp endpoint in app-token/oidc mode. OAuth mode uses user JWTs
	// instead and does not require this.
	HTTPSecret string // OCIS_MCP_HTTP_SECRET

	// Logging
	LogLevel string // OCIS_MCP_LOG_LEVEL (default: "info")

	// Security
	Insecure      bool          // OCIS_MCP_INSECURE
	TLSSkipVerify bool          // OCIS_MCP_TLS_SKIP_VERIFY
	HTTPTimeout   time.Duration // OCIS_MCP_HTTP_TIMEOUT (default: 30s)
}

// Load reads configuration from environment variables and validates it.
func Load() (*Config, error) {
	cfg := &Config{
		OcisURL:              os.Getenv("OCIS_MCP_OCIS_URL"),
		AuthMode:             os.Getenv("OCIS_MCP_AUTH_MODE"),
		AppTokenUser:         os.Getenv("OCIS_MCP_APP_TOKEN_USER"),
		AppTokenValue:        os.Getenv("OCIS_MCP_APP_TOKEN_VALUE"),
		OidcIssuer:           os.Getenv("OCIS_MCP_OIDC_ISSUER"),
		OidcClientID:         os.Getenv("OCIS_MCP_OIDC_CLIENT_ID"),
		OidcClientSecret:     os.Getenv("OCIS_MCP_OIDC_CLIENT_SECRET"),
		OidcAccessToken:      os.Getenv("OCIS_MCP_OIDC_ACCESS_TOKEN"),
		PublicURL:            os.Getenv("OCIS_MCP_PUBLIC_URL"),
		GrantDB:              os.Getenv("OCIS_MCP_GRANT_DB"),
		GrantKey:             os.Getenv("OCIS_MCP_GRANT_KEY"),
		EducationAccessToken: os.Getenv("OCIS_MCP_EDUCATION_ACCESS_TOKEN"),
		Transport:            os.Getenv("OCIS_MCP_TRANSPORT"),
		HTTPAddr:             os.Getenv("OCIS_MCP_HTTP_ADDR"),
		HTTPSecret:           os.Getenv("OCIS_MCP_HTTP_SECRET"),
		LogLevel:             os.Getenv("OCIS_MCP_LOG_LEVEL"),
		Insecure:             envBool("OCIS_MCP_INSECURE"),
		TLSSkipVerify:        envBool("OCIS_MCP_TLS_SKIP_VERIFY"),
	}

	if cfg.Transport == "" {
		cfg.Transport = "stdio"
	}
	if cfg.HTTPAddr == "" {
		cfg.HTTPAddr = "127.0.0.1:8090"
	}
	if cfg.LogLevel == "" {
		cfg.LogLevel = "info"
	}
	if cfg.GrantDB == "" {
		cfg.GrantDB = "data/grants.db"
	}

	timeout := os.Getenv("OCIS_MCP_HTTP_TIMEOUT")
	if timeout == "" {
		cfg.HTTPTimeout = 30 * time.Second
	} else {
		d, err := time.ParseDuration(timeout)
		if err != nil {
			return nil, fmt.Errorf("invalid OCIS_MCP_HTTP_TIMEOUT %q: %w", timeout, err)
		}
		cfg.HTTPTimeout = d
	}

	if err := cfg.validate(); err != nil {
		return nil, err
	}

	cfg.AuthMode = selectAuthMode(cfg)
	return cfg, nil
}

func (c *Config) validate() error {
	if c.OcisURL == "" {
		return fmt.Errorf("OCIS_MCP_OCIS_URL is required")
	}

	u, err := url.Parse(c.OcisURL)
	if err != nil {
		return fmt.Errorf("invalid OCIS_MCP_OCIS_URL %q: %w", c.OcisURL, err)
	}

	if u.Scheme == "http" && !c.Insecure {
		return fmt.Errorf("OCIS_MCP_OCIS_URL uses plaintext HTTP. Set OCIS_MCP_INSECURE=true to allow this (dev only)")
	}

	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("OCIS_MCP_OCIS_URL must use http or https scheme, got %q", u.Scheme)
	}

	if c.Transport != "stdio" && c.Transport != "http" {
		return fmt.Errorf("OCIS_MCP_TRANSPORT must be 'stdio' or 'http', got %q", c.Transport)
	}

	oauth := strings.EqualFold(c.AuthMode, "oauth")
	if oauth {
		if c.Transport != "http" {
			return fmt.Errorf("OCIS_MCP_AUTH_MODE=oauth requires OCIS_MCP_TRANSPORT=http")
		}
		if c.PublicURL == "" {
			return fmt.Errorf("OCIS_MCP_PUBLIC_URL is required in oauth mode (the URL MCP clients open)")
		}
		if pu, err := url.Parse(c.PublicURL); err != nil || (pu.Scheme != "http" && pu.Scheme != "https") {
			return fmt.Errorf("invalid OCIS_MCP_PUBLIC_URL %q", c.PublicURL)
		}
		if c.OidcClientID == "" {
			return fmt.Errorf("OCIS_MCP_OIDC_CLIENT_ID is required in oauth mode (same client as the oCIS compose stack, plus /oauth/callback redirect)")
		}
		if c.GrantKey == "" {
			return fmt.Errorf("OCIS_MCP_GRANT_KEY is required in oauth mode (32-byte hex, e.g. openssl rand -hex 32)")
		}
		if _, err := secretbox.ParseKey(c.GrantKey); err != nil {
			return fmt.Errorf("OCIS_MCP_GRANT_KEY: %w", err)
		}
	}

	// Shared-secret gate for the legacy HTTP transport. OAuth mode authenticates
	// /mcp with user JWTs, so a static secret is not required.
	if c.Transport == "http" && !oauth && c.HTTPSecret == "" && !isLoopbackHost(c.HTTPAddr) {
		return fmt.Errorf(
			"OCIS_MCP_TRANSPORT=http is bound to non-loopback address %q with no authentication: "+
				"set OCIS_MCP_HTTP_SECRET, or OCIS_MCP_AUTH_MODE=oauth, or bind to a loopback address", c.HTTPAddr)
	}

	hasAppToken := c.AppTokenUser != "" && c.AppTokenValue != ""
	hasOIDC := c.OidcAccessToken != ""
	if hasAppToken && hasOIDC && c.AuthMode == "" {
		return fmt.Errorf("both app-token and OIDC credentials are set. Set OCIS_MCP_AUTH_MODE explicitly")
	}

	return nil
}

func selectAuthMode(cfg *Config) string {
	if cfg.AuthMode != "" {
		return cfg.AuthMode
	}
	if cfg.AppTokenUser != "" && cfg.AppTokenValue != "" {
		return "app-token"
	}
	if cfg.OidcAccessToken != "" {
		return "oidc"
	}
	return "none"
}

func (c *Config) NewHTTPClient() *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if c.TLSSkipVerify {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec
	}
	return &http.Client{
		Timeout:   c.HTTPTimeout,
		Transport: transport,
	}
}

func (c *Config) OcisBaseURL() string {
	return strings.TrimRight(c.OcisURL, "/")
}

func (c *Config) HTTPAuthEnabled() bool {
	return c.HTTPSecret != "" || strings.EqualFold(c.AuthMode, "oauth")
}

func (c *Config) IsLoopbackBind() bool {
	return isLoopbackHost(c.HTTPAddr)
}

func isLoopbackHost(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	switch host {
	case "":
		return false
	case "localhost":
		return true
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	return ip.IsLoopback()
}

func envBool(key string) bool {
	v := os.Getenv(key)
	b, _ := strconv.ParseBool(v)
	return b
}
