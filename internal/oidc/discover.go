// Package oidc talks to the same OpenID Provider that oCIS uses.
//
// We never invent a second login: we read
//
//	{OCIS_URL}/.well-known/openid-configuration
//
// (oCIS proxies this to Authentik / LibreGraph Connect) or an explicit
// OCIS_MCP_OIDC_ISSUER. The user sees the normal oCIS login page.
package oidc

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"golang.org/x/oauth2"
)

type Disco struct {
	Issuer                string   `json:"issuer"`
	AuthorizationEndpoint string   `json:"authorization_endpoint"`
	TokenEndpoint         string   `json:"token_endpoint"`
	UserinfoEndpoint      string   `json:"userinfo_endpoint"`
	JWKSURI               string   `json:"jwks_uri"`
	ScopesSupported       []string `json:"scopes_supported"`
}

func Discover(ctx context.Context, hc *http.Client, issuerOrOcis string) (*Disco, error) {
	base := strings.TrimRight(issuerOrOcis, "/")
	url := base + "/.well-known/openid-configuration"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("OIDC discovery %s: %w", url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("OIDC discovery %s: HTTP %d", url, resp.StatusCode)
	}
	var d Disco
	if err := json.NewDecoder(resp.Body).Decode(&d); err != nil {
		return nil, fmt.Errorf("decoding discovery: %w", err)
	}
	if d.AuthorizationEndpoint == "" || d.TokenEndpoint == "" {
		return nil, fmt.Errorf("discovery document missing authorization/token endpoints")
	}
	return &d, nil
}

func Config(d *Disco, clientID, clientSecret, redirectURL string) *oauth2.Config {
	return &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		Scopes:       []string{"openid", "profile", "email", "offline_access"},
		Endpoint: oauth2.Endpoint{
			AuthURL:  d.AuthorizationEndpoint,
			TokenURL: d.TokenEndpoint,
		},
	}
}

type UserInfo struct {
	Sub           string `json:"sub"`
	Name          string `json:"name"`
	PreferredName string `json:"preferred_username"`
	Email         string `json:"email"`
}

func FetchUserInfo(ctx context.Context, hc *http.Client, userinfoURL, accessToken string) (UserInfo, error) {
	var u UserInfo
	if userinfoURL == "" {
		return u, fmt.Errorf("no userinfo endpoint")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, userinfoURL, nil)
	if err != nil {
		return u, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	resp, err := hc.Do(req)
	if err != nil {
		return u, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return u, fmt.Errorf("userinfo HTTP %d", resp.StatusCode)
	}
	if err := json.NewDecoder(resp.Body).Decode(&u); err != nil {
		return u, err
	}
	return u, nil
}

// SubjectFromAccessToken reads `sub` from an unverified JWT payload.
// Used only as a fallback when userinfo is locked down; the token itself
// was just issued to us over TLS by the IdP.
func SubjectFromAccessToken(raw string) string {
	parts := strings.Split(raw, ".")
	if len(parts) < 2 {
		return ""
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		payload, err = base64.URLEncoding.DecodeString(parts[1])
		if err != nil {
			return ""
		}
	}
	var claims struct {
		Sub string `json:"sub"`
	}
	if json.Unmarshal(payload, &claims) != nil {
		return ""
	}
	return claims.Sub
}

// TokenExpiryUnix converts oauth2.Token expiry to unix seconds.
func TokenExpiryUnix(tok *oauth2.Token) int64 {
	if tok == nil || tok.Expiry.IsZero() {
		return time.Now().Add(time.Hour).Unix()
	}
	return tok.Expiry.Unix()
}
