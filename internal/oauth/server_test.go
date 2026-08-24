package oauth

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/owncloud/ocis-mcp-server/internal/grant"
	"github.com/owncloud/ocis-mcp-server/internal/store"
)

func testOA(t *testing.T) (*Server, *store.Store) {
	t.Helper()
	key := bytes.Repeat([]byte{0x33}, 32)
	st, err := store.Open(filepath.Join(t.TempDir(), "g.db"), key)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	s := NewServer("https://mcp.example.com", key, key, st)
	return s, st
}

func TestASMetadata(t *testing.T) {
	s, _ := testOA(t)
	rr := httptest.NewRecorder()
	s.ASMetadata(rr, httptest.NewRequest(http.MethodGet, "/", nil))
	if rr.Code != 200 {
		t.Fatal(rr.Code)
	}
	var body map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &body)
	if body["issuer"] != "https://mcp.example.com" {
		t.Fatalf("%v", body)
	}
}

func TestRegisterAndTokenPKCE(t *testing.T) {
	s, st := testOA(t)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/register", strings.NewReader(`{"redirect_uris":["http://127.0.0.1:9/cb"],"client_name":"Test"}`))
	s.Register(rr, req)
	if rr.Code != 201 {
		t.Fatalf("register %d %s", rr.Code, rr.Body.String())
	}
	var reg map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &reg)
	cid := reg["client_id"].(string)

	g := &grant.Grant{ID: "g1", UserID: "u", ClientID: cid}
	if err := st.PutGrant(g); err != nil {
		t.Fatal(err)
	}
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])
	if err := st.PutAuthCode("code1", "g1", cid, "http://127.0.0.1:9/cb", challenge, time.Minute); err != nil {
		t.Fatal(err)
	}

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {"code1"},
		"code_verifier": {verifier},
		"redirect_uri":  {"http://127.0.0.1:9/cb"},
		"client_id":     {cid},
	}
	tr := httptest.NewRecorder()
	treq := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	treq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	s.Token(tr, treq)
	if tr.Code != 200 {
		t.Fatalf("token %d %s", tr.Code, tr.Body.String())
	}
	var tok map[string]any
	_ = json.Unmarshal(tr.Body.Bytes(), &tok)
	if tok["token_type"] != "Bearer" || tok["access_token"] == nil {
		t.Fatalf("%v", tok)
	}

	// replay code
	tr2 := httptest.NewRecorder()
	treq2 := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(form.Encode()))
	treq2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	s.Token(tr2, treq2)
	if tr2.Code != 400 {
		t.Fatal("replay must fail")
	}
}

func TestRegisterRejectsHTTPNonLoopback(t *testing.T) {
	s, _ := testOA(t)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/register", strings.NewReader(`{"redirect_uris":["http://evil.example/cb"]}`))
	s.Register(rr, req)
	if rr.Code != 400 {
		t.Fatalf("got %d", rr.Code)
	}
}

func TestSessionCookieHMAC(t *testing.T) {
	s, _ := testOA(t)
	rr := httptest.NewRecorder()
	s.SetSessionCookie(rr, "abc")
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	for _, c := range rr.Result().Cookies() {
		req.AddCookie(c)
	}
	sid, ok := s.ReadSessionCookie(req)
	if !ok || sid != "abc" {
		t.Fatalf("%q %v", sid, ok)
	}
	req2 := httptest.NewRequest(http.MethodGet, "/", nil)
	req2.AddCookie(&http.Cookie{Name: "ocis_mcp_session", Value: "abc.deadbeef"})
	if _, ok := s.ReadSessionCookie(req2); ok {
		t.Fatal("tampered cookie")
	}
}
