package oauth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/owncloud/ocis-mcp-server/internal/store"
)

// Server is the OAuth 2.1 authorization server that MCP clients talk to.
// Login itself is delegated to oCIS's IdP; we only issue MCP tokens after
// the consent wizard finishes.
type Server struct {
	PublicURL    string
	Issuer       string
	Audience     string
	JWTKey       []byte
	CookieKey    []byte
	Store        *store.Store
	CookieSecure bool
	AccessTTL    time.Duration
	RefreshTTL   time.Duration
	CodeTTL      time.Duration
}

func NewServer(publicURL string, jwtKey, cookieKey []byte, st *store.Store) *Server {
	pub := strings.TrimRight(publicURL, "/")
	return &Server{
		PublicURL:    pub,
		Issuer:       pub,
		Audience:     pub + "/mcp",
		JWTKey:       jwtKey,
		CookieKey:    cookieKey,
		Store:        st,
		CookieSecure: strings.HasPrefix(pub, "https://"),
		AccessTTL:    15 * time.Minute,
		RefreshTTL:   30 * 24 * time.Hour,
		CodeTTL:      5 * time.Minute,
	}
}

func (s *Server) ResourceMetadata(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"resource":                 s.Audience,
		"authorization_servers":    []string{s.Issuer},
		"bearer_methods_supported": []string{"header"},
		"scopes_supported":         []string{"ocis-mcp"},
	})
}

func (s *Server) ASMetadata(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"issuer":                                s.Issuer,
		"authorization_endpoint":                s.PublicURL + "/authorize",
		"token_endpoint":                        s.PublicURL + "/token",
		"revocation_endpoint":                   s.PublicURL + "/revoke",
		"registration_endpoint":                 s.PublicURL + "/register",
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code", "refresh_token"},
		"code_challenge_methods_supported":      []string{"S256"},
		"token_endpoint_auth_methods_supported": []string{"none", "client_secret_post", "client_secret_basic"},
		"scopes_supported":                      []string{"ocis-mcp"},
	})
}

// Register implements a small RFC 7591 DCR so Claude/Cursor can onboard
// without a pre-shared client id.
func (s *Server) Register(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		RedirectURIs []string `json:"redirect_uris"`
		ClientName   string   `json:"client_name"`
		TokenAuth    string   `json:"token_endpoint_auth_method"`
	}
	_ = json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&body)
	if len(body.RedirectURIs) == 0 {
		http.Error(w, "redirect_uris required", http.StatusBadRequest)
		return
	}
	for _, u := range body.RedirectURIs {
		if !ValidRedirectURI(u) {
			http.Error(w, "redirect_uri must be https or http loopback", http.StatusBadRequest)
			return
		}
	}
	id := "mcp-" + RandomToken()[:24]
	name := body.ClientName
	if name == "" {
		name = "MCP client"
	}
	c := store.Client{ID: id, Name: name, RedirectURIs: body.RedirectURIs}
	if err := s.Store.PutClient(c); err != nil {
		http.Error(w, "could not register client", http.StatusInternalServerError)
		return
	}
	s.Store.Audit("client.register", "", id, name)
	writeJSON(w, http.StatusCreated, map[string]any{
		"client_id":                  id,
		"client_name":                name,
		"redirect_uris":              body.RedirectURIs,
		"token_endpoint_auth_method": "none",
		"grant_types":                []string{"authorization_code", "refresh_token"},
		"response_types":             []string{"code"},
		"code_challenge_methods":     []string{"S256"},
	})
}

// ValidRedirectURI allows https anywhere, and http only on loopback
// (RFC 8252 native apps / MCP desktop clients).
func ValidRedirectURI(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.Fragment != "" {
		return false
	}
	switch strings.ToLower(u.Scheme) {
	case "https":
		return true
	case "http":
		host := strings.ToLower(u.Hostname())
		return host == "127.0.0.1" || host == "localhost" || host == "::1"
	default:
		return false
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func (s *Server) WWWAuthenticate() string {
	return `Bearer realm="ocis-mcp", resource_metadata="` + s.PublicURL + `/.well-known/oauth-protected-resource"`
}

func (s *Server) SetSessionCookie(w http.ResponseWriter, sid string) {
	mac := hmac.New(sha256.New, s.CookieKey)
	_, _ = mac.Write([]byte(sid))
	val := sid + "." + hex.EncodeToString(mac.Sum(nil))
	http.SetCookie(w, &http.Cookie{
		Name:     "ocis_mcp_session",
		Value:    val,
		Path:     "/",
		HttpOnly: true,
		Secure:   s.CookieSecure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int((30 * time.Minute).Seconds()),
	})
}

func (s *Server) ReadSessionCookie(r *http.Request) (string, bool) {
	c, err := r.Cookie("ocis_mcp_session")
	if err != nil {
		return "", false
	}
	sid, mac, ok := strings.Cut(c.Value, ".")
	if !ok || sid == "" {
		return "", false
	}
	want := hmac.New(sha256.New, s.CookieKey)
	_, _ = want.Write([]byte(sid))
	got, err := hex.DecodeString(mac)
	if err != nil {
		return "", false
	}
	if !hmac.Equal(got, want.Sum(nil)) {
		return "", false
	}
	return sid, true
}

func (s *Server) Token(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		tokenErr(w, "invalid_request", "malformed body")
		return
	}
	switch r.FormValue("grant_type") {
	case "authorization_code":
		s.tokenCode(w, r)
	case "refresh_token":
		s.tokenRefresh(w, r)
	default:
		tokenErr(w, "unsupported_grant_type", "")
	}
}

func (s *Server) tokenCode(w http.ResponseWriter, r *http.Request) {
	code := r.FormValue("code")
	verifier := r.FormValue("code_verifier")
	redirect := r.FormValue("redirect_uri")
	clientID := r.FormValue("client_id")
	grantID, cid, redir, challenge, err := s.Store.ConsumeAuthCode(code)
	if err != nil {
		slog.Info("token code rejected", "err", err)
		tokenErr(w, "invalid_grant", "invalid code")
		return
	}
	if cid != clientID || redir != redirect {
		tokenErr(w, "invalid_grant", "client/redirect mismatch")
		return
	}
	if !VerifyS256(verifier, challenge) {
		tokenErr(w, "invalid_grant", "pkce failed")
		return
	}
	s.issue(w, grantID, clientID)
}

func (s *Server) tokenRefresh(w http.ResponseWriter, r *http.Request) {
	raw := r.FormValue("refresh_token")
	grantID, clientID, err := s.Store.ConsumeRefresh(raw)
	if err != nil {
		tokenErr(w, "invalid_grant", "invalid refresh token")
		return
	}
	s.issue(w, grantID, clientID)
}

func (s *Server) issue(w http.ResponseWriter, grantID, clientID string) {
	g, err := s.Store.GetGrant(grantID)
	if err != nil {
		tokenErr(w, "invalid_grant", "grant missing")
		return
	}
	access, err := SignAccess(s.JWTKey, s.Issuer, s.Audience, g.UserID, grantID, clientID, s.AccessTTL)
	if err != nil {
		tokenErr(w, "server_error", "")
		return
	}
	refresh := RandomToken()
	if err := s.Store.PutRefresh(refresh, grantID, clientID, s.RefreshTTL); err != nil {
		tokenErr(w, "server_error", "")
		return
	}
	s.Store.Audit("token.issue", g.UserID, clientID, grantID)
	writeJSON(w, http.StatusOK, map[string]any{
		"access_token":  access,
		"token_type":    "Bearer",
		"expires_in":    int(s.AccessTTL.Seconds()),
		"refresh_token": refresh,
		"scope":         "ocis-mcp",
	})
}

func (s *Server) Revoke(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	tok := r.FormValue("token")
	if tok != "" {
		_, _, _ = s.Store.ConsumeRefresh(tok)
	}
	w.WriteHeader(http.StatusOK)
}

func tokenErr(w http.ResponseWriter, code, desc string) {
	body := map[string]string{"error": code}
	if desc != "" {
		body["error_description"] = desc
	}
	writeJSON(w, http.StatusBadRequest, body)
}
