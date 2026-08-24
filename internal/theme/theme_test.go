package theme

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestFallback(t *testing.T) {
	th := Fallback()
	if th.Brand != "#041e42" || th.Name != "ownCloud" {
		t.Fatalf("%+v", th)
	}
	if !strings.Contains(th.CSS(), "--oc-brand: #041e42") {
		t.Fatal(th.CSS())
	}
}

func TestFetchParsesThemeJSON(t *testing.T) {
	body := `{
		"common": {"name": "Contoso Files", "slogan": "safe", "logo": "/logo.svg"},
		"clients": {
			"web": {
				"defaults": {"logo": {"topbar": "/top.svg"}},
				"themes": [{
					"designTokens": {
						"colorPalette": {
							"swatch-brand-default": "#123456",
							"swatch-brand-hover": "#654321",
							"swatch-brand-contrast": "#ffffff",
							"background-default": "#eeeeee"
						}
					}
				}]
			}
		}
	}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/themes/owncloud/theme.json" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()
	th := Fetch(context.Background(), srv.Client(), srv.URL)
	if th.Name != "Contoso Files" || th.Brand != "#123456" {
		t.Fatalf("%+v", th)
	}
	if !strings.HasSuffix(th.LogoURL, "/top.svg") {
		t.Fatalf("logo %s", th.LogoURL)
	}
}

func TestFetchFallsBackOnError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(404)
	}))
	defer srv.Close()
	th := Fetch(context.Background(), srv.Client(), srv.URL)
	if th.Name != "ownCloud" {
		t.Fatalf("%+v", th)
	}
}
