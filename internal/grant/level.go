// Package grant is the heart of "what did the user actually allow?".
//
// After oCIS login, the consent wizard records a Grant: a list of spaces
// plus an optional instance-admin flag. Every MCP tool call is checked
// against that Grant before we talk to oCIS.
package grant

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

// Level is the permission the user chose for one space.
// Higher values include the lower ones (admin implies write implies read).
type Level int

const (
	LevelNone  Level = 0
	LevelRead  Level = 1
	LevelWrite Level = 2
	LevelAdmin Level = 3
)

func (l Level) String() string {
	switch l {
	case LevelRead:
		return "read"
	case LevelWrite:
		return "write"
	case LevelAdmin:
		return "admin"
	default:
		return "none"
	}
}

// ParseLevel maps the consent form values to a Level.
func ParseLevel(s string) Level {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "read", "viewer", "view":
		return LevelRead
	case "write", "editor", "edit":
		return LevelWrite
	case "admin", "manager", "owner":
		return LevelAdmin
	default:
		return LevelNone
	}
}

// AtLeast reports whether l is as strong as need.
func (l Level) AtLeast(need Level) bool {
	return l >= need
}

// SpaceGrant is one row on the confirmation screen.
type SpaceGrant struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	DriveType   string `json:"drive_type"`
	Level       Level  `json:"level"`
	Ceiling     Level  `json:"ceiling"` // highest role the user has in oCIS
	Description string `json:"description,omitempty"`
}

// Grant is stored server-side and referenced by the MCP access token.
// Putting the space list in SQLite (not in the JWT) means we can revoke
// without waiting for the JWT to expire.
type Grant struct {
	ID             string       `json:"id"`
	UserID         string       `json:"user_id"`
	UserName       string       `json:"user_name"`
	ClientID       string       `json:"client_id"`
	Spaces         []SpaceGrant `json:"spaces"`
	InstanceAdmin  bool         `json:"instance_admin"`
	OcisAccess     string       `json:"-"` // never JSON-log this
	OcisRefresh    string       `json:"-"`
	OcisExpiryUnix int64        `json:"ocis_expiry_unix,omitempty"`
}

// SpaceLevel returns the consented level for a space ID, or LevelNone.
func (g *Grant) SpaceLevel(spaceID string) Level {
	if g == nil {
		return LevelNone
	}
	for _, s := range g.Spaces {
		if s.ID == spaceID {
			return s.Level
		}
	}
	return LevelNone
}

type ctxKey struct{}

// WithContext attaches a Grant to ctx so tool handlers and HTTP client
// auth can see it without a global variable.
func WithContext(ctx context.Context, g *Grant) context.Context {
	return context.WithValue(ctx, ctxKey{}, g)
}

// FromContext returns the Grant, if any. Missing grant means "legacy
// app-token / static OIDC mode" — callers should not enforce space ACL.
func FromContext(ctx context.Context) (*Grant, bool) {
	g, ok := ctx.Value(ctxKey{}).(*Grant)
	return g, ok && g != nil
}

// MarshalSpaces is a helper for the SQLite column.
func MarshalSpaces(ss []SpaceGrant) (string, error) {
	b, err := json.Marshal(ss)
	return string(b), err
}

func UnmarshalSpaces(s string) ([]SpaceGrant, error) {
	if s == "" {
		return nil, nil
	}
	var ss []SpaceGrant
	if err := json.Unmarshal([]byte(s), &ss); err != nil {
		return nil, fmt.Errorf("decoding space grants: %w", err)
	}
	return ss, nil
}
