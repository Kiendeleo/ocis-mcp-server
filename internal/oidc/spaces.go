package oidc

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/owncloud/ocis-mcp-server/internal/grant"
)

type graphDrive struct {
	ID             string   `json:"id"`
	Name           string   `json:"name"`
	DriveType      string   `json:"driveType"`
	Description    string   `json:"description"`
	EffectiveRoles []string `json:"@libre.graph.permissions.roles.effective"`
	Root           *struct {
		Permissions []struct {
			Roles []string `json:"roles"`
		} `json:"permissions"`
	} `json:"root"`
}

type graphList struct {
	Value []graphDrive `json:"value"`
}

// AccessibleSpaces lists personal + project spaces the token can see and
// computes the oCIS role ceiling (what the consent radios may offer).
func AccessibleSpaces(ctx context.Context, hc *http.Client, ocisURL, accessToken string) ([]grant.SpaceGrant, error) {
	url := strings.TrimRight(ocisURL, "/") + "/graph/v1.0/me/drives"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")
	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("listing spaces: HTTP %d", resp.StatusCode)
	}
	var list graphList
	if err := json.NewDecoder(resp.Body).Decode(&list); err != nil {
		return nil, err
	}
	var out []grant.SpaceGrant
	for _, d := range list.Value {
		if d.DriveType == "virtual" {
			continue
		}
		roles := append([]string{}, d.EffectiveRoles...)
		if d.Root != nil {
			for _, p := range d.Root.Permissions {
				roles = append(roles, p.Roles...)
			}
		}
		ceil := grant.CeilingFromRoles(roles)
		if ceil == grant.LevelNone && d.DriveType == "personal" {
			ceil = grant.LevelAdmin // owner of personal space
		}
		if ceil == grant.LevelNone {
			ceil = grant.LevelRead
		}
		out = append(out, grant.SpaceGrant{
			ID:          d.ID,
			Name:        d.Name,
			DriveType:   d.DriveType,
			Ceiling:     ceil,
			Level:       grant.LevelNone,
			Description: d.Description,
		})
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].DriveType == "personal" && out[j].DriveType != "personal" {
			return true
		}
		if out[j].DriveType == "personal" && out[i].DriveType != "personal" {
			return false
		}
		return out[i].Name < out[j].Name
	})
	return out, nil
}

// IsInstanceAdmin probes an admin-only Graph call. 403/401 → not admin.
func IsInstanceAdmin(ctx context.Context, hc *http.Client, ocisURL, accessToken string) bool {
	url := strings.TrimRight(ocisURL, "/") + "/graph/v1.0/users?$top=1"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return false
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	resp, err := hc.Do(req)
	if err != nil {
		return false
	}
	defer func() { _ = resp.Body.Close() }()
	return resp.StatusCode >= 200 && resp.StatusCode < 300
}
