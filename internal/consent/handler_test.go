package consent

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/owncloud/ocis-mcp-server/internal/grant"
	"github.com/owncloud/ocis-mcp-server/internal/oauth"
	"github.com/owncloud/ocis-mcp-server/internal/oidc"
	"github.com/owncloud/ocis-mcp-server/internal/store"
	"github.com/owncloud/ocis-mcp-server/internal/theme"
	"golang.org/x/oauth2"
)

func TestAuthorizeRedirectsToIdP(t *testing.T) {
	key := bytes.Repeat([]byte{0x11}, 32)
	st, err := store.Open(filepath.Join(t.TempDir(), "g.db"), key)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	if err := st.PutClient(store.Client{ID: "mcp-1", Name: "T", RedirectURIs: []string{"http://127.0.0.1:9/cb"}}); err != nil {
		t.Fatal(err)
	}
	oa := oauth.NewServer("https://mcp.example.com", key, key, st)
	h := &Handler{
		OAuth: oa,
		Store: st,
		Theme: theme.Fallback(),
		OAuth2: &oauth2.Config{
			ClientID:    "ocis",
			RedirectURL: "https://mcp.example.com/oauth/callback",
			Endpoint:    oauth2.Endpoint{AuthURL: "https://id.example/auth", TokenURL: "https://id.example/token"},
		},
		Disco:      &oidc.Disco{AuthorizationEndpoint: "https://id.example/auth"},
		SessionTTL: time.Minute,
	}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/authorize?client_id=mcp-1&redirect_uri=http://127.0.0.1:9/cb&code_challenge=abc&code_challenge_method=S256&state=st", nil)
	h.Authorize(rr, req)
	if rr.Code != http.StatusFound {
		t.Fatalf("code %d body %s", rr.Code, rr.Body.String())
	}
	loc := rr.Header().Get("Location")
	if loc == "" || !containsAll(loc, "https://id.example/auth", "code_challenge") {
		t.Fatalf("location %s", loc)
	}
}

func TestAuthorizeRejectsUnknownClient(t *testing.T) {
	key := bytes.Repeat([]byte{0x11}, 32)
	st, err := store.Open(filepath.Join(t.TempDir(), "g.db"), key)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	h := &Handler{
		OAuth:      oauth.NewServer("https://mcp.example.com", key, key, st),
		Store:      st,
		SessionTTL: time.Minute,
		OAuth2:     &oauth2.Config{Endpoint: oauth2.Endpoint{AuthURL: "https://id.example/auth"}},
	}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/authorize?client_id=nope&redirect_uri=http://127.0.0.1:9/cb&code_challenge=abc", nil)
	h.Authorize(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatal(rr.Code)
	}
}

func containsAll(s string, parts ...string) bool {
	for _, p := range parts {
		if !bytes.Contains([]byte(s), []byte(p)) {
			return false
		}
	}
	return true
}

func testHandler(t *testing.T) (*Handler, *store.Store, []byte) {
	t.Helper()
	key := bytes.Repeat([]byte{0x11}, 32)
	st, err := store.Open(filepath.Join(t.TempDir(), "g.db"), key)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	if err := st.PutClient(store.Client{ID: "mcp-1", Name: "Claude", RedirectURIs: []string{"http://127.0.0.1:9/cb"}}); err != nil {
		t.Fatal(err)
	}
	oa := oauth.NewServer("https://mcp.example.com", key, key, st)
	h := &Handler{
		OAuth:      oa,
		Store:      st,
		Theme:      theme.Fallback(),
		SessionTTL: time.Hour,
		OAuth2: &oauth2.Config{
			ClientID:    "ocis",
			RedirectURL: "https://mcp.example.com/oauth/callback",
			Endpoint:    oauth2.Endpoint{AuthURL: "https://id.example/auth", TokenURL: "https://id.example/token"},
		},
		Disco: &oidc.Disco{AuthorizationEndpoint: "https://id.example/auth"},
	}
	return h, st, key
}

func cookieReq(h *Handler, method, target, sid string, form string) *http.Request {
	var req *http.Request
	if form != "" {
		req = httptest.NewRequest(method, target, strings.NewReader(form))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	} else {
		req = httptest.NewRequest(method, target, nil)
	}
	rr := httptest.NewRecorder()
	h.OAuth.SetSessionCookie(rr, sid)
	for _, c := range rr.Result().Cookies() {
		req.AddCookie(c)
	}
	return req
}

func TestWizardSpacesLevelsConfirm(t *testing.T) {
	h, st, _ := testHandler(t)
	f := &Flow{
		CSRF:     "tok",
		ClientID: "mcp-1",
		RedirectURI: "http://127.0.0.1:9/cb",
		State:    "st",
		CodeChallenge: "challenge",
		UserID:   "user-1",
		UserName: "Ada",
		OcisAccess: "acc",
		Spaces: []grant.SpaceGrant{
			{ID: "p1", Name: "Personal", DriveType: "personal", Ceiling: grant.LevelAdmin},
			{ID: "x", Name: "Other", DriveType: "project", Ceiling: grant.LevelRead},
		},
		InstanceAdminOK: true,
		Step:            "spaces",
	}
	sid := store.RandomID()
	if err := h.saveFlow(sid, f); err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	h.SpacesGET(rr, cookieReq(h, http.MethodGet, "/consent/spaces", sid, ""))
	if rr.Code != 200 || !bytes.Contains(rr.Body.Bytes(), []byte("Personal")) {
		t.Fatalf("%d %s", rr.Code, rr.Body.String())
	}

	rr = httptest.NewRecorder()
	h.SpacesPOST(rr, cookieReq(h, http.MethodPost, "/consent/spaces", sid, "csrf=tok&space=p1"))
	if rr.Code != http.StatusFound || rr.Header().Get("Location") != "/consent/levels" {
		t.Fatalf("spaces post %d %s", rr.Code, rr.Header().Get("Location"))
	}

	rr = httptest.NewRecorder()
	h.LevelsGET(rr, cookieReq(h, http.MethodGet, "/consent/levels", sid, ""))
	if !bytes.Contains(rr.Body.Bytes(), []byte("Instance administration")) {
		t.Fatalf("levels should show instance admin: %s", rr.Body.String())
	}

	rr = httptest.NewRecorder()
	h.LevelsPOST(rr, cookieReq(h, http.MethodPost, "/consent/levels", sid, "csrf=tok&level_p1=write&instance_admin=1"))
	if rr.Header().Get("Location") != "/consent/confirm" {
		t.Fatal(rr.Header().Get("Location"))
	}

	rr = httptest.NewRecorder()
	h.ConfirmGET(rr, cookieReq(h, http.MethodGet, "/consent/confirm", sid, ""))
	if !bytes.Contains(rr.Body.Bytes(), []byte("Claude")) {
		t.Fatal(rr.Body.String())
	}

	rr = httptest.NewRecorder()
	h.ConfirmPOST(rr, cookieReq(h, http.MethodPost, "/consent/confirm", sid, "csrf=tok"))
	if rr.Code != http.StatusFound {
		t.Fatal(rr.Body.String())
	}
	loc := rr.Header().Get("Location")
	if !strings.Contains(loc, "http://127.0.0.1:9/cb") || !strings.Contains(loc, "code=") {
		t.Fatalf("redirect %s", loc)
	}

	// grant persisted
	rows, err := st.GetClient("mcp-1")
	if err != nil || rows.Name != "Claude" {
		t.Fatal(err)
	}
}

func TestSpacesPOSTRequiresSelection(t *testing.T) {
	h, _, _ := testHandler(t)
	f := &Flow{
		CSRF: "tok", ClientID: "mcp-1",
		Spaces: []grant.SpaceGrant{{ID: "p1", Name: "P", Ceiling: grant.LevelRead}},
	}
	sid := store.RandomID()
	_ = h.saveFlow(sid, f)
	rr := httptest.NewRecorder()
	h.SpacesPOST(rr, cookieReq(h, http.MethodPost, "/consent/spaces", sid, "csrf=tok"))
	if rr.Code != 200 || !bytes.Contains(rr.Body.Bytes(), []byte("Select at least one")) {
		t.Fatalf("%d %s", rr.Code, rr.Body.String())
	}
}

func TestCSRFRejected(t *testing.T) {
	h, _, _ := testHandler(t)
	f := &Flow{CSRF: "real", ClientID: "mcp-1", Spaces: []grant.SpaceGrant{{ID: "p1"}}}
	sid := store.RandomID()
	_ = h.saveFlow(sid, f)
	rr := httptest.NewRecorder()
	h.SpacesPOST(rr, cookieReq(h, http.MethodPost, "/consent/spaces", sid, "csrf=wrong&space=p1"))
	if rr.Code != http.StatusBadRequest {
		t.Fatal(rr.Code)
	}
}

func TestExpiredSession(t *testing.T) {
	h, _, _ := testHandler(t)
	rr := httptest.NewRecorder()
	h.SpacesGET(rr, httptest.NewRequest(http.MethodGet, "/consent/spaces", nil))
	if rr.Code != http.StatusUnauthorized {
		t.Fatal(rr.Code)
	}
}

