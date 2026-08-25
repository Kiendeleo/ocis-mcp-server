// Package httpapi wires OAuth metadata, the consent wizard, and the MCP
// Streamable HTTP endpoint onto one listener.
package httpapi

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/owncloud/ocis-mcp-server/internal/client"
	"github.com/owncloud/ocis-mcp-server/internal/config"
	"github.com/owncloud/ocis-mcp-server/internal/consent"
	"github.com/owncloud/ocis-mcp-server/internal/grant"
	"github.com/owncloud/ocis-mcp-server/internal/middleware"
	"github.com/owncloud/ocis-mcp-server/internal/oauth"
	"github.com/owncloud/ocis-mcp-server/internal/oidc"
	"github.com/owncloud/ocis-mcp-server/internal/secretbox"
	"github.com/owncloud/ocis-mcp-server/internal/store"
	"github.com/owncloud/ocis-mcp-server/internal/theme"
	"golang.org/x/oauth2"
)

type Deps struct {
	Cfg    *config.Config
	Client *client.Client
	MCP    *mcp.Server
}

// ListenAndServe starts the HTTP transport. In oauth mode it hosts the
// authorization server + consent UI; /mcp then requires a user grant JWT.
func ListenAndServe(ctx context.Context, d Deps) error {
	cfg := d.Cfg
	mux := http.NewServeMux()

	mcpHandler := mcp.NewStreamableHTTPHandler(
		func(_ *http.Request) *mcp.Server { return d.MCP },
		nil,
	)

	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	})

	if cfg.AuthMode == "oauth" {
		st, oa, cons, err := setupOAuth(ctx, cfg)
		if err != nil {
			return err
		}
		defer func() { _ = st.Close() }()

		d.MCP.AddReceivingMiddleware(grantMiddleware)

		mux.HandleFunc("/.well-known/oauth-protected-resource", oa.ResourceMetadata)
		mux.HandleFunc("/.well-known/oauth-protected-resource/mcp", oa.ResourceMetadata)
		mux.HandleFunc("/mcp/.well-known/oauth-protected-resource", oa.ResourceMetadata)
		mux.HandleFunc("/.well-known/oauth-authorization-server", oa.ASMetadata)
		mux.HandleFunc("/.well-known/oauth-authorization-server/mcp", oa.ASMetadata)
		mux.HandleFunc("/register", oa.Register)
		mux.HandleFunc("/authorize", cons.Authorize)
		mux.HandleFunc("/oauth/callback", cons.Callback)
		mux.HandleFunc("/token", oa.Token)
		mux.HandleFunc("/revoke", oa.Revoke)
		mux.HandleFunc("/consent/spaces", method(cons.SpacesGET, cons.SpacesPOST))
		mux.HandleFunc("/consent/levels", method(cons.LevelsGET, cons.LevelsPOST))
		mux.HandleFunc("/consent/confirm", method(cons.ConfirmGET, cons.ConfirmPOST))

		secured := middleware.SecurityHeaders(mcpBearer(oa, st, d.Client)(mcpHandler))
		mux.Handle("/mcp", secured)
		mux.Handle("/mcp/", secured)
		slog.Info("OAuth 2.1 resource server enabled", "issuer", oa.Issuer, "resource", oa.Audience)
	} else {
		mux.Handle("/mcp", middleware.SecurityHeaders(middleware.RequireBearer(cfg.HTTPSecret)(mcpHandler)))
		if !cfg.HTTPAuthEnabled() {
			slog.Warn("HTTP transport is UNAUTHENTICATED (OCIS_MCP_HTTP_SECRET not set): any client that can reach this address can invoke every tool with the server's oCIS credentials. Set OCIS_MCP_HTTP_SECRET or OCIS_MCP_AUTH_MODE=oauth.",
				"addr", cfg.HTTPAddr)
		}
	}

	if !cfg.IsLoopbackBind() {
		slog.Warn("HTTP server bound to a non-loopback interface — ensure this is intentional and network-restricted",
			"addr", cfg.HTTPAddr)
	}

	srv := &http.Server{
		Addr:              cfg.HTTPAddr,
		Handler:           withCORS(mux),
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() {
		<-ctx.Done()
		_ = srv.Close()
	}()
	slog.Info("HTTP transport listening", "addr", cfg.HTTPAddr, "auth_mode", cfg.AuthMode, "authenticated", cfg.HTTPAuthEnabled())
	err := srv.ListenAndServe()
	if err == http.ErrServerClosed {
		return nil
	}
	return err
}

func setupOAuth(ctx context.Context, cfg *config.Config) (*store.Store, *oauth.Server, *consent.Handler, error) {
	master, err := secretbox.ParseKey(cfg.GrantKey)
	if err != nil {
		return nil, nil, nil, err
	}
	colKey := secretbox.Derive(master, "columns")
	jwtKey := secretbox.Derive(master, "jwt")
	cookieKey := secretbox.Derive(master, "cookie")

	st, err := store.Open(cfg.GrantDB, colKey)
	if err != nil {
		return nil, nil, nil, err
	}

	issuer := cfg.OidcIssuer
	if issuer == "" {
		issuer = cfg.OcisBaseURL()
	}
	hc := cfg.NewHTTPClient()
	disco, err := oidc.Discover(ctx, hc, issuer)
	if err != nil {
		_ = st.Close()
		return nil, nil, nil, err
	}
	redirect := strings.TrimRight(cfg.PublicURL, "/") + "/oauth/callback"
	oa2 := oidc.Config(disco, cfg.OidcClientID, cfg.OidcClientSecret, redirect)

	oa := oauth.NewServer(cfg.PublicURL, jwtKey, cookieKey, st)
	th := theme.Fetch(ctx, hc, cfg.OcisBaseURL())
	cons := &consent.Handler{
		OAuth:      oa,
		Store:      st,
		Theme:      th,
		OcisURL:    cfg.OcisBaseURL(),
		HTTPClient: hc,
		OAuth2:     oa2,
		Disco:      disco,
		SessionTTL: 30 * time.Minute,
	}
	return st, oa, cons, nil
}

func method(get, post http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			get(w, r)
		case http.MethodPost:
			post(w, r)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	}
}

func withCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, MCP-Protocol-Version")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func mcpBearer(oa *oauth.Server, st *store.Store, ocis *client.Client) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			raw := bearer(r)
			if raw == "" {
				w.Header().Set("WWW-Authenticate", oa.WWWAuthenticate())
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			claims, err := oauth.ParseAccess(oa.JWTKey, oa.Issuer, oa.Audience, raw)
			if err != nil {
				w.Header().Set("WWW-Authenticate", oa.WWWAuthenticate())
				http.Error(w, "invalid token", http.StatusUnauthorized)
				return
			}
			g, err := st.GetGrant(claims.GrantID)
			if err != nil {
				w.Header().Set("WWW-Authenticate", oa.WWWAuthenticate())
				http.Error(w, "grant revoked or missing", http.StatusUnauthorized)
				return
			}
			g = maybeRefresh(r.Context(), st, ocis, g)
			ctx := grant.WithContext(r.Context(), g)
			ctx = client.WithAuth(ctx, client.RequestAuth{OcisAccessToken: g.OcisAccess, GrantID: g.ID})
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func maybeRefresh(ctx context.Context, st *store.Store, ocis *client.Client, g *grant.Grant) *grant.Grant {
	if g.OcisExpiryUnix == 0 || time.Now().Unix() < g.OcisExpiryUnix-60 {
		return g
	}
	if g.OcisRefresh == "" {
		return g
	}
	cfg := ocis.Config()
	issuer := cfg.OidcIssuer
	if issuer == "" {
		issuer = cfg.OcisBaseURL()
	}
	disco, err := oidc.Discover(ctx, cfg.NewHTTPClient(), issuer)
	if err != nil {
		slog.Warn("ocis token refresh: discovery failed", "err", err)
		return g
	}
	oa2 := oidc.Config(disco, cfg.OidcClientID, cfg.OidcClientSecret, strings.TrimRight(cfg.PublicURL, "/")+"/oauth/callback")
	src := oa2.TokenSource(ctx, &oauth2.Token{RefreshToken: g.OcisRefresh})
	tok, err := src.Token()
	if err != nil {
		slog.Warn("ocis token refresh failed", "err", err)
		return g
	}
	g.OcisAccess = tok.AccessToken
	if tok.RefreshToken != "" {
		g.OcisRefresh = tok.RefreshToken
	}
	g.OcisExpiryUnix = oidc.TokenExpiryUnix(tok)
	if err := st.UpdateOcisTokens(g.ID, g.OcisAccess, g.OcisRefresh, g.OcisExpiryUnix); err != nil {
		slog.Warn("persist refreshed token failed", "err", err)
	}
	return g
}

func bearer(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if len(h) > 7 && strings.EqualFold(h[:7], "Bearer ") {
		return strings.TrimSpace(h[7:])
	}
	return ""
}

func grantMiddleware(next mcp.MethodHandler) mcp.MethodHandler {
	return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
		g, ok := grant.FromContext(ctx)
		if !ok {
			return next(ctx, method, req)
		}
		switch method {
		case "tools/call":
			if p, ok := req.GetParams().(*mcp.CallToolParamsRaw); ok && p != nil && p.Name != "" {
				if err := grant.Allow(g, p.Name, p.Arguments); err != nil {
					return nil, err
				}
			} else {
				p := req.GetParams()
				raw, _ := json.Marshal(p)
				var wrap struct {
					Name      string          `json:"name"`
					Arguments json.RawMessage `json:"arguments"`
				}
				_ = json.Unmarshal(raw, &wrap)
				if wrap.Name != "" {
					if err := grant.Allow(g, wrap.Name, wrap.Arguments); err != nil {
						return nil, err
					}
				}
			}
		case "tools/list":
			res, err := next(ctx, method, req)
			if err != nil {
				return res, err
			}
			return filterListedTools(g, res), nil
		}
		return next(ctx, method, req)
	}
}

func filterListedTools(g *grant.Grant, res mcp.Result) mcp.Result {
	list, ok := res.(*mcp.ListToolsResult)
	if !ok || list == nil {
		return res
	}
	names := make([]string, 0, len(list.Tools))
	byName := make(map[string]*mcp.Tool, len(list.Tools))
	for _, t := range list.Tools {
		if t == nil {
			continue
		}
		names = append(names, t.Name)
		byName[t.Name] = t
	}
	keep := grant.VisibleTools(g, names)
	out := make([]*mcp.Tool, 0, len(keep))
	for _, n := range keep {
		if t, ok := byName[n]; ok {
			out = append(out, t)
		}
	}
	filtered := *list
	filtered.Tools = out
	return &filtered
}
