package httpapi

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/owncloud/ocis-mcp-server/internal/grant"
	"github.com/owncloud/ocis-mcp-server/internal/oauth"
	"github.com/owncloud/ocis-mcp-server/internal/store"
)

func TestBearer(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	if bearer(r) != "" {
		t.Fatal("empty")
	}
	r.Header.Set("Authorization", "Bearer abc")
	if bearer(r) != "abc" {
		t.Fatal(bearer(r))
	}
}

func TestWithCORSPreflight(t *testing.T) {
	h := withCORS(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	}))
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodOptions, "/mcp", nil)
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusNoContent {
		t.Fatal(rr.Code)
	}
	if rr.Header().Get("Access-Control-Allow-Origin") != "*" {
		t.Fatal(rr.Header())
	}
}

func TestFilterListedTools(t *testing.T) {
	if filterListedTools(&grant.Grant{}, nil) != nil {
		t.Fatal("nil")
	}
	g := &grant.Grant{Spaces: []grant.SpaceGrant{{ID: "s", Level: grant.LevelRead}}}
	in := &mcp.ListToolsResult{Tools: []*mcp.Tool{
		{Name: "ocis_health_check"},
		{Name: "ocis_create_user"},
		{Name: "ocis_list_files"},
		{Name: "ocis_upload_file"},
	}}
	out := filterListedTools(g, in).(*mcp.ListToolsResult)
	got := map[string]bool{}
	for _, tl := range out.Tools {
		got[tl.Name] = true
	}
	if !got["ocis_health_check"] || !got["ocis_list_files"] {
		t.Fatalf("%v", got)
	}
	if got["ocis_create_user"] || got["ocis_upload_file"] {
		t.Fatalf("should hide admin/write: %v", got)
	}
}

func TestMethodDispatch(t *testing.T) {
	h := method(
		func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) },
		func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusCreated) },
	)
	rr := httptest.NewRecorder()
	h(rr, httptest.NewRequest(http.MethodGet, "/", nil))
	if rr.Code != 200 {
		t.Fatal(rr.Code)
	}
	rr = httptest.NewRecorder()
	h(rr, httptest.NewRequest(http.MethodPost, "/", nil))
	if rr.Code != 201 {
		t.Fatal(rr.Code)
	}
	rr = httptest.NewRecorder()
	h(rr, httptest.NewRequest(http.MethodDelete, "/", nil))
	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatal(rr.Code)
	}
}

func TestMCPBearer(t *testing.T) {
	key := bytes.Repeat([]byte{0x44}, 32)
	st, err := store.Open(filepath.Join(t.TempDir(), "g.db"), key)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	g := &grant.Grant{ID: "g1", UserID: "u", ClientID: "c", OcisAccess: "ocis-tok"}
	if err := st.PutGrant(g); err != nil {
		t.Fatal(err)
	}
	oa := oauth.NewServer("https://mcp.example.com", key, key, st)
	tok, err := oauth.SignAccess(key, oa.Issuer, oa.Audience, "u", "g1", "c", time.Minute)
	if err != nil {
		t.Fatal(err)
	}

	var sawGrant bool
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if gr, ok := grant.FromContext(r.Context()); ok && gr.ID == "g1" {
			sawGrant = true
		}
		w.WriteHeader(http.StatusNoContent)
	})
	h := mcpBearer(oa, st, nil)(next)

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/mcp", nil))
	if rr.Code != http.StatusUnauthorized {
		t.Fatal("missing token")
	}

	rr = httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/mcp", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusNoContent || !sawGrant {
		t.Fatalf("valid token %d grant=%v", rr.Code, sawGrant)
	}

	rr = httptest.NewRecorder()
	bad := httptest.NewRequest(http.MethodGet, "/mcp", nil)
	bad.Header.Set("Authorization", "Bearer not-a-jwt")
	h.ServeHTTP(rr, bad)
	if rr.Code != http.StatusUnauthorized {
		t.Fatal(rr.Code)
	}
}

func TestMaybeRefreshSkipsFreshToken(t *testing.T) {
	g := &grant.Grant{OcisExpiryUnix: time.Now().Add(time.Hour).Unix(), OcisAccess: "a"}
	got := maybeRefresh(nil, nil, nil, g)
	if got.OcisAccess != "a" {
		t.Fatal("should not touch fresh token")
	}
}
