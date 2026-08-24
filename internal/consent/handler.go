package consent

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/owncloud/ocis-mcp-server/internal/grant"
	"github.com/owncloud/ocis-mcp-server/internal/oauth"
	"github.com/owncloud/ocis-mcp-server/internal/oidc"
	"github.com/owncloud/ocis-mcp-server/internal/store"
	"github.com/owncloud/ocis-mcp-server/internal/theme"
	"golang.org/x/oauth2"
)

type Handler struct {
	OAuth      *oauth.Server
	Store      *store.Store
	Theme      theme.Theme
	OcisURL    string
	HTTPClient *http.Client
	OAuth2     *oauth2.Config
	Disco      *oidc.Disco
	SessionTTL time.Duration
}

func (h *Handler) loadFlow(r *http.Request) (sid string, f *Flow, err error) {
	sid, ok := h.OAuth.ReadSessionCookie(r)
	if !ok {
		return "", nil, fmt.Errorf("no session")
	}
	raw, err := h.Store.GetSession(sid)
	if err != nil {
		return sid, nil, err
	}
	f, err = UnmarshalFlow(raw)
	return sid, f, err
}

func (h *Handler) saveFlow(sid string, f *Flow) error {
	b, err := f.Marshal()
	if err != nil {
		return err
	}
	return h.Store.PutSession(sid, b, h.SessionTTL)
}

func (h *Handler) csrfOK(r *http.Request, f *Flow) bool {
	return f != nil && f.CSRF != "" && r.FormValue("csrf") == f.CSRF
}

func csrf() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// Authorize is /authorize — validate the MCP client, stash PKCE, send the
// browser to the real oCIS login.
func (h *Handler) Authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	clientID := q.Get("client_id")
	redirect := q.Get("redirect_uri")
	state := q.Get("state")
	challenge := q.Get("code_challenge")
	method := q.Get("code_challenge_method")
	resource := q.Get("resource")

	if clientID == "" || redirect == "" || challenge == "" {
		http.Error(w, "client_id, redirect_uri and code_challenge are required (OAuth 2.1 + PKCE)", http.StatusBadRequest)
		return
	}
	if method != "" && !strings.EqualFold(method, "S256") {
		http.Error(w, "only S256 PKCE is supported", http.StatusBadRequest)
		return
	}
	if resource != "" && resource != h.OAuth.Audience && resource != h.OAuth.Issuer {
		http.Error(w, "resource does not match this MCP server", http.StatusBadRequest)
		return
	}
	cl, err := h.Store.GetClient(clientID)
	if err != nil {
		http.Error(w, "unknown client_id — register at /register first", http.StatusBadRequest)
		return
	}
	if !cl.ValidRedirect(redirect) {
		http.Error(w, "redirect_uri is not registered for this client", http.StatusBadRequest)
		return
	}

	sid := store.RandomID()
	upVerifier := oauth.RandomToken()
	f := &Flow{
		CSRF:             csrf(),
		ClientID:         clientID,
		RedirectURI:      redirect,
		State:            state,
		CodeChallenge:    challenge,
		UpstreamVerifier: upVerifier,
		Resource:         resource,
		Step:             "login",
	}
	if err := h.saveFlow(sid, f); err != nil {
		http.Error(w, "session store failed", http.StatusInternalServerError)
		return
	}
	h.OAuth.SetSessionCookie(w, sid)

	sum := sha256.Sum256([]byte(upVerifier))
	upChallenge := base64.RawURLEncoding.EncodeToString(sum[:])
	authURL := h.OAuth2.AuthCodeURL(sid,
		oauth2.AccessTypeOffline,
		oauth2.SetAuthURLParam("code_challenge", upChallenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	)
	http.Redirect(w, r, authURL, http.StatusFound)
}

// Callback is /oauth/callback after Authentik/oCIS login.
func (h *Handler) Callback(w http.ResponseWriter, r *http.Request) {
	if errMsg := r.URL.Query().Get("error"); errMsg != "" {
		http.Error(w, "login failed: "+errMsg, http.StatusUnauthorized)
		return
	}
	code := r.URL.Query().Get("code")
	st := r.URL.Query().Get("state")
	sid, f, err := h.loadFlow(r)
	if err != nil || sid != st {
		http.Error(w, "login session mismatch — start again from your MCP client", http.StatusBadRequest)
		return
	}
	tok, err := h.OAuth2.Exchange(r.Context(), code, oauth2.SetAuthURLParam("code_verifier", f.UpstreamVerifier))
	if err != nil {
		slog.Info("upstream token exchange failed", "err", err)
		http.Error(w, "could not complete oCIS login", http.StatusUnauthorized)
		return
	}
	ui, err := oidc.FetchUserInfo(r.Context(), h.HTTPClient, h.Disco.UserinfoEndpoint, tok.AccessToken)
	if err != nil {
		slog.Info("userinfo failed, continuing with token subject", "err", err)
	}
	if ui.Sub == "" {
		ui.Sub = oidc.SubjectFromAccessToken(tok.AccessToken)
	}
	spaces, err := oidc.AccessibleSpaces(r.Context(), h.HTTPClient, h.OcisURL, tok.AccessToken)
	if err != nil {
		http.Error(w, "logged in, but could not list your spaces: "+err.Error(), http.StatusBadGateway)
		return
	}
	if len(spaces) == 0 {
		http.Error(w, "your account has no spaces to share", http.StatusForbidden)
		return
	}
	f.OcisAccess = tok.AccessToken
	f.OcisRefresh = tok.RefreshToken
	f.OcisExpiryUnix = oidc.TokenExpiryUnix(tok)
	f.UserID = ui.Sub
	f.UserName = firstNonEmpty(ui.Name, ui.PreferredName, ui.Email, ui.Sub)
	f.InstanceAdminOK = oidc.IsInstanceAdmin(r.Context(), h.HTTPClient, h.OcisURL, tok.AccessToken)
	f.Spaces = spaces
	f.Step = "spaces"
	if err := h.saveFlow(sid, f); err != nil {
		http.Error(w, "session store failed", http.StatusInternalServerError)
		return
	}
	h.Store.Audit("login.ok", f.UserID, f.ClientID, "")
	http.Redirect(w, r, "/consent/spaces", http.StatusFound)
}

func (h *Handler) SpacesGET(w http.ResponseWriter, r *http.Request) {
	_, f, err := h.loadFlow(r)
	if err != nil {
		http.Error(w, "session expired — reconnect your MCP client", http.StatusUnauthorized)
		return
	}
	sel := map[string]bool{}
	for _, id := range f.Selected {
		sel[id] = true
	}
	writeHTML(w, SpacesPage(h.Theme, f.CSRF, f.Spaces, sel))
}

func (h *Handler) SpacesPOST(w http.ResponseWriter, r *http.Request) {
	sid, f, err := h.loadFlow(r)
	if err != nil {
		http.Error(w, "session expired", http.StatusUnauthorized)
		return
	}
	if err := r.ParseForm(); err != nil || !h.csrfOK(r, f) {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	ids := r.Form["space"]
	if len(ids) == 0 {
		writeHTML(w, ErrorPage(h.Theme, "Select at least one space."))
		return
	}
	allow := map[string]bool{}
	for _, s := range f.Spaces {
		allow[s.ID] = true
	}
	var selected []string
	for _, id := range ids {
		if allow[id] {
			selected = append(selected, id)
		}
	}
	if len(selected) == 0 {
		writeHTML(w, ErrorPage(h.Theme, "Select at least one space you have access to."))
		return
	}
	f.Selected = selected
	f.Step = "levels"
	_ = h.saveFlow(sid, f)
	http.Redirect(w, r, "/consent/levels", http.StatusFound)
}

func (h *Handler) selectedSpaces(f *Flow) []grant.SpaceGrant {
	want := map[string]bool{}
	for _, id := range f.Selected {
		want[id] = true
	}
	var out []grant.SpaceGrant
	for _, s := range f.Spaces {
		if want[s.ID] {
			out = append(out, s)
		}
	}
	return out
}

func (h *Handler) LevelsGET(w http.ResponseWriter, r *http.Request) {
	_, f, err := h.loadFlow(r)
	if err != nil {
		http.Error(w, "session expired", http.StatusUnauthorized)
		return
	}
	writeHTML(w, LevelsPage(h.Theme, f.CSRF, h.selectedSpaces(f), f.InstanceAdminOK, f.WantInstanceAdm))
}

func (h *Handler) LevelsPOST(w http.ResponseWriter, r *http.Request) {
	sid, f, err := h.loadFlow(r)
	if err != nil {
		http.Error(w, "session expired", http.StatusUnauthorized)
		return
	}
	if err := r.ParseForm(); err != nil || !h.csrfOK(r, f) {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	byID := map[string]int{}
	for i, s := range f.Spaces {
		byID[s.ID] = i
	}
	for _, id := range f.Selected {
		i, ok := byID[id]
		if !ok {
			continue
		}
		want := grant.ParseLevel(r.FormValue("level_" + id))
		f.Spaces[i].Level = grant.ClampLevel(want, f.Spaces[i].Ceiling)
		if f.Spaces[i].Level == grant.LevelNone {
			f.Spaces[i].Level = grant.LevelRead
		}
	}
	f.WantInstanceAdm = f.InstanceAdminOK && r.FormValue("instance_admin") == "1"
	f.Step = "confirm"
	_ = h.saveFlow(sid, f)
	http.Redirect(w, r, "/consent/confirm", http.StatusFound)
}

func (h *Handler) ConfirmGET(w http.ResponseWriter, r *http.Request) {
	_, f, err := h.loadFlow(r)
	if err != nil {
		http.Error(w, "session expired", http.StatusUnauthorized)
		return
	}
	cl, _ := h.Store.GetClient(f.ClientID)
	name := cl.Name
	if name == "" {
		name = f.ClientID
	}
	writeHTML(w, ConfirmPage(h.Theme, f.CSRF, name, h.selectedSpaces(f), f.WantInstanceAdm))
}

func (h *Handler) ConfirmPOST(w http.ResponseWriter, r *http.Request) {
	sid, f, err := h.loadFlow(r)
	if err != nil {
		http.Error(w, "session expired", http.StatusUnauthorized)
		return
	}
	if err := r.ParseForm(); err != nil || !h.csrfOK(r, f) {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	g := &grant.Grant{
		ID:             store.RandomID(),
		UserID:         f.UserID,
		UserName:       f.UserName,
		ClientID:       f.ClientID,
		Spaces:         h.selectedSpaces(f),
		InstanceAdmin:  f.WantInstanceAdm,
		OcisAccess:     f.OcisAccess,
		OcisRefresh:    f.OcisRefresh,
		OcisExpiryUnix: f.OcisExpiryUnix,
	}
	if err := h.Store.PutGrant(g); err != nil {
		http.Error(w, "could not save grant", http.StatusInternalServerError)
		return
	}
	code := oauth.RandomToken()
	if err := h.Store.PutAuthCode(code, g.ID, f.ClientID, f.RedirectURI, f.CodeChallenge, h.OAuth.CodeTTL); err != nil {
		http.Error(w, "could not issue code", http.StatusInternalServerError)
		return
	}
	h.Store.DeleteSession(sid)
	h.Store.Audit("consent.granted", f.UserID, f.ClientID, g.ID)

	u, err := url.Parse(f.RedirectURI)
	if err != nil {
		http.Error(w, "bad redirect", http.StatusBadRequest)
		return
	}
	q := u.Query()
	q.Set("code", code)
	if f.State != "" {
		q.Set("state", f.State)
	}
	u.RawQuery = q.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}

func writeHTML(w http.ResponseWriter, body string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; img-src 'self' https: data:; form-action 'self'")
	_, _ = w.Write([]byte(body))
}

func firstNonEmpty(ss ...string) string {
	for _, s := range ss {
		if strings.TrimSpace(s) != "" {
			return s
		}
	}
	return ""
}
