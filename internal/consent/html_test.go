package consent

import (
	"strings"
	"testing"

	"github.com/owncloud/ocis-mcp-server/internal/grant"
	"github.com/owncloud/ocis-mcp-server/internal/theme"
)

func TestSpacesPageListsPersonalAndEscapes(t *testing.T) {
	th := theme.Fallback()
	html := SpacesPage(th, "csrf-token", []grant.SpaceGrant{
		{ID: "p1", Name: "Acme & Co", DriveType: "personal", Ceiling: grant.LevelAdmin},
		{ID: "x", Name: "Project", DriveType: "project", Ceiling: grant.LevelRead},
	}, map[string]bool{"p1": true})
	if !strings.Contains(html, "csrf-token") || !strings.Contains(html, "Personal space") {
		t.Fatal("missing expected copy")
	}
	if strings.Contains(html, "Acme & Co") {
		t.Fatal("ampersand must be escaped")
	}
	escaped := "Acme " + "&" + "amp;" + " Co"
	if !strings.Contains(html, escaped) {
		t.Fatalf("escaped name missing\n%s", html)
	}
}

func TestLevelsPageHidesInstanceAdminUnlessOK(t *testing.T) {
	th := theme.Fallback()
	spaces := []grant.SpaceGrant{{ID: "p1", Name: "Mine", Ceiling: grant.LevelRead, Level: grant.LevelRead}}
	no := LevelsPage(th, "c", spaces, false, false)
	if strings.Contains(no, "Instance administration") {
		t.Fatal("must not offer instance admin")
	}
	if strings.Contains(no, `value="write"`) || strings.Contains(no, `value="admin"`) {
		t.Fatal("viewer must not see write/admin radios")
	}
	yes := LevelsPage(th, "c", spaces, true, false)
	if !strings.Contains(yes, "Instance administration") {
		t.Fatal("oCIS admin should see the checkbox")
	}
}

func TestConfirmPageSummarizes(t *testing.T) {
	th := theme.Fallback()
	html := ConfirmPage(th, "c", "Claude", []grant.SpaceGrant{
		{Name: "Mine", Level: grant.LevelRead},
	}, true)
	if !strings.Contains(html, "Claude") || !strings.Contains(html, "Instance administration") {
		t.Fatal(html)
	}
}

func TestFlowMarshalRestoresTokens(t *testing.T) {
	f := &Flow{CSRF: "x", OcisAccess: "acc", OcisRefresh: "ref", UserID: "u"}
	b, err := f.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	got, err := UnmarshalFlow(b)
	if err != nil {
		t.Fatal(err)
	}
	if got.OcisAccess != "acc" || got.OcisRefresh != "ref" || got.UserID != "u" {
		t.Fatalf("%+v", got)
	}
}
