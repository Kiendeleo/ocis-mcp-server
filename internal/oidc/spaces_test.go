package oidc

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/owncloud/ocis-mcp-server/internal/grant"
)

func TestAccessibleSpacesPersonalFirstAndCeiling(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/graph/v1.0/me/drives" {
			t.Errorf("path %s", r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer tok" {
			t.Errorf("auth %s", r.Header.Get("Authorization"))
		}
		_, _ = w.Write([]byte(`{"value":[
			{"id":"p2","name":"Zed","driveType":"project","@libre.graph.permissions.roles.effective":["viewer"]},
			{"id":"p1","name":"Ada","driveType":"personal"},
			{"id":"v1","name":"Shares","driveType":"virtual"},
			{"id":"p3","name":"Beta","driveType":"project","root":{"permissions":[{"roles":["manager"]}]}}
		]}`))
	}))
	defer srv.Close()

	spaces, err := AccessibleSpaces(context.Background(), srv.Client(), srv.URL, "tok")
	if err != nil {
		t.Fatal(err)
	}
	if len(spaces) != 3 {
		t.Fatalf("len=%d (virtual should drop)", len(spaces))
	}
	if spaces[0].DriveType != "personal" || spaces[0].Ceiling != grant.LevelAdmin {
		t.Fatalf("personal first with admin ceiling: %+v", spaces[0])
	}
	if spaces[1].Name != "Beta" || spaces[1].Ceiling != grant.LevelAdmin {
		t.Fatalf("beta %+v", spaces[1])
	}
	if spaces[2].Name != "Zed" || spaces[2].Ceiling != grant.LevelRead {
		t.Fatalf("zed %+v", spaces[2])
	}
}

func TestIsInstanceAdmin(t *testing.T) {
	ok := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`{"value":[]}`))
	}))
	defer ok.Close()
	if !IsInstanceAdmin(context.Background(), ok.Client(), ok.URL, "t") {
		t.Fatal("200 should be admin")
	}
	forbid := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(403)
	}))
	defer forbid.Close()
	if IsInstanceAdmin(context.Background(), forbid.Client(), forbid.URL, "t") {
		t.Fatal("403 is not admin")
	}
}

func TestDiscover(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/openid-configuration" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{
			"issuer":                 "https://id.example",
			"authorization_endpoint": "https://id.example/auth",
			"token_endpoint":         "https://id.example/token",
			"userinfo_endpoint":      "https://id.example/userinfo",
		})
	}))
	defer srv.Close()
	d, err := Discover(context.Background(), srv.Client(), srv.URL)
	if err != nil || d.TokenEndpoint != "https://id.example/token" {
		t.Fatalf("%+v %v", d, err)
	}
}

func TestSubjectFromAccessToken(t *testing.T) {
	payload := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"user-42"}`))
	raw := "header." + payload + ".sig"
	if got := SubjectFromAccessToken(raw); got != "user-42" {
		t.Fatalf("got %q", got)
	}
	if SubjectFromAccessToken("not-a-jwt") != "" {
		t.Fatal("garbage")
	}
}

func TestFetchUserInfo(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"sub": "s", "name": "N"})
	}))
	defer srv.Close()
	ui, err := FetchUserInfo(context.Background(), srv.Client(), srv.URL, "t")
	if err != nil || ui.Sub != "s" {
		t.Fatalf("%+v %v", ui, err)
	}
}
