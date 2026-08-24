// Package theme loads the oCIS Web theme.json so consent pages match
// the files instance (logo, brand navy, slogan).
package theme

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// Theme is the subset of oCIS Web theme.json we actually paint with.
type Theme struct {
	Name       string
	Slogan     string
	LogoURL    string
	Brand      string
	BrandHover string
	Contrast   string
	Background string
}

func Fallback() Theme {
	return Theme{
		Name:       "ownCloud",
		Slogan:     "A safe home for all your data",
		LogoURL:    "",
		Brand:      "#041e42",
		BrandHover: "#223959",
		Contrast:   "#ffffff",
		Background: "#f5f7fa",
	}
}

type rawTheme struct {
	Common struct {
		Name   string `json:"name"`
		Slogan string `json:"slogan"`
		Logo   string `json:"logo"`
	} `json:"common"`
	Clients struct {
		Web struct {
			Defaults struct {
				Logo struct {
					Topbar string `json:"topbar"`
				} `json:"logo"`
			} `json:"defaults"`
			Themes []struct {
				DesignTokens struct {
					ColorPalette map[string]string `json:"colorPalette"`
				} `json:"designTokens"`
			} `json:"themes"`
		} `json:"web"`
	} `json:"clients"`
}

func Fetch(ctx context.Context, hc *http.Client, ocisURL string) Theme {
	t := Fallback()
	base := strings.TrimRight(ocisURL, "/")
	paths := []string{
		"/themes/owncloud/theme.json",
		"/owncloud/themes/owncloud/theme.json",
	}
	var body []byte
	for _, p := range paths {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+p, nil)
		if err != nil {
			continue
		}
		resp, err := hc.Do(req)
		if err != nil {
			continue
		}
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		_ = resp.Body.Close()
		if resp.StatusCode == http.StatusOK && len(b) > 0 {
			body = b
			break
		}
	}
	if len(body) == 0 {
		return t
	}
	var raw rawTheme
	if err := json.Unmarshal(body, &raw); err != nil {
		return t
	}
	if raw.Common.Name != "" {
		t.Name = raw.Common.Name
	}
	if raw.Common.Slogan != "" {
		t.Slogan = raw.Common.Slogan
	}
	logo := raw.Clients.Web.Defaults.Logo.Topbar
	if logo == "" {
		logo = raw.Common.Logo
	}
	if logo != "" {
		if strings.HasPrefix(logo, "http") {
			t.LogoURL = logo
		} else {
			t.LogoURL = base + "/" + strings.TrimLeft(logo, "/")
		}
	}
	if len(raw.Clients.Web.Themes) > 0 {
		p := raw.Clients.Web.Themes[0].DesignTokens.ColorPalette
		if v := p["swatch-brand-default"]; v != "" {
			t.Brand = v
		}
		if v := p["swatch-brand-hover"]; v != "" {
			t.BrandHover = v
		}
		if v := p["swatch-brand-contrast"]; v != "" {
			t.Contrast = v
		}
		if v := p["background-default"]; v != "" {
			t.Background = v
		}
	}
	return t
}

func (t Theme) CSS() string {
	return fmt.Sprintf(`:root {
  --oc-brand: %s;
  --oc-brand-hover: %s;
  --oc-contrast: %s;
  --oc-bg: %s;
}`, t.Brand, t.BrandHover, t.Contrast, t.Background)
}
