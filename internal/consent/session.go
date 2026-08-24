package consent

import (
	"encoding/json"

	"github.com/owncloud/ocis-mcp-server/internal/grant"
)

// Flow is the encrypted session blob for the 3-step wizard.
type Flow struct {
	CSRF            string            `json:"csrf"`
	ClientID        string            `json:"client_id"`
	RedirectURI     string            `json:"redirect_uri"`
	State           string            `json:"state"`        // MCP client's OAuth state
	CodeChallenge   string            `json:"code_challenge"`
	UpstreamVerifier string           `json:"upstream_verifier,omitempty"`
	Resource        string            `json:"resource"`
	UserID          string            `json:"user_id"`
	UserName        string            `json:"user_name"`
	OcisAccess      string            `json:"-"`
	OcisRefresh     string            `json:"-"`
	OcisExpiryUnix  int64             `json:"ocis_exp"`
	InstanceAdminOK bool              `json:"instance_admin_ok"` // user IS an oCIS admin
	WantInstanceAdm bool              `json:"want_instance_adm"`
	Spaces          []grant.SpaceGrant `json:"spaces"`
	Selected        []string          `json:"selected"`
	Step            string            `json:"step"` // spaces | levels | confirm
	Tokens          tokenBag          `json:"tokens"`
}

// tokenBag is JSON-serialized inside the encrypted session so we don't
// put oCIS tokens in cookies in plaintext (the whole Flow is encrypted).
type tokenBag struct {
	Access  string `json:"a"`
	Refresh string `json:"r"`
}

func (f *Flow) Marshal() ([]byte, error) {
	f.Tokens = tokenBag{Access: f.OcisAccess, Refresh: f.OcisRefresh}
	return json.Marshal(f)
}

func UnmarshalFlow(b []byte) (*Flow, error) {
	var f Flow
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, err
	}
	f.OcisAccess, f.OcisRefresh = f.Tokens.Access, f.Tokens.Refresh
	return &f, nil
}
