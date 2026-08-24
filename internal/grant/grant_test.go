package grant

import (
	"encoding/json"
	"testing"
)

func TestClampAndOffer(t *testing.T) {
	if ClampLevel(LevelAdmin, LevelRead) != LevelRead {
		t.Fatal("cannot consent above oCIS role")
	}
	off := LevelsOffered(LevelWrite)
	if len(off) != 2 || off[0] != LevelRead || off[1] != LevelWrite {
		t.Fatalf("offered = %v", off)
	}
	if len(LevelsOffered(LevelRead)) != 1 {
		t.Fatal("viewer should only see read")
	}
	if len(LevelsOffered(LevelNone)) != 0 {
		t.Fatal("none offers nothing")
	}
}

func TestMapOcisRole(t *testing.T) {
	cases := map[string]Level{
		"manager":     LevelAdmin,
		"Manager":     LevelAdmin,
		"space admin": LevelAdmin,
		"owner":       LevelAdmin,
		"editor":      LevelWrite,
		"writer":      LevelWrite,
		"uploader":    LevelWrite,
		"viewer":      LevelRead,
		"reader":      LevelRead,
		"guest":       LevelRead,
		"":            LevelNone,
		"deadbeef":    LevelRead, // unknown UUID → read, never write
	}
	for in, want := range cases {
		if got := MapOcisRole(in); got != want {
			t.Errorf("MapOcisRole(%q)=%s want %s", in, got, want)
		}
	}
}

func TestParseLevel(t *testing.T) {
	if ParseLevel("viewer") != LevelRead || ParseLevel("edit") != LevelWrite || ParseLevel("manager") != LevelAdmin {
		t.Fatal("aliases")
	}
	if ParseLevel("nope") != LevelNone {
		t.Fatal("unknown")
	}
}

func TestCeilingFromRoles(t *testing.T) {
	if CeilingFromRoles([]string{"viewer", "manager"}) != LevelAdmin {
		t.Fatal("max")
	}
}

func TestAllowSpaceAndAdmin(t *testing.T) {
	g := &Grant{
		Spaces: []SpaceGrant{
			{ID: "sp1", Level: LevelRead},
			{ID: "sp2", Level: LevelWrite},
		},
	}
	if err := Allow(g, "ocis_list_files", json.RawMessage(`{"space_id":"sp1"}`)); err != nil {
		t.Fatal(err)
	}
	if err := Allow(g, "ocis_upload_file", json.RawMessage(`{"space_id":"sp1"}`)); err == nil {
		t.Fatal("read grant must not upload")
	}
	if err := Allow(g, "ocis_upload_file", json.RawMessage(`{"space_id":"sp2"}`)); err != nil {
		t.Fatal(err)
	}
	if err := Allow(g, "ocis_create_user", nil); err == nil {
		t.Fatal("instance admin required")
	}
	g.InstanceAdmin = true
	if err := Allow(g, "ocis_create_user", nil); err != nil {
		t.Fatal(err)
	}
	if err := Allow(g, "ocis_health_check", nil); err != nil {
		t.Fatal(err)
	}
}

func TestAllowDriveIDAlias(t *testing.T) {
	g := &Grant{Spaces: []SpaceGrant{{ID: "d1", Level: LevelRead}}}
	if err := Allow(g, "ocis_list_files", json.RawMessage(`{"drive_id":"d1"}`)); err != nil {
		t.Fatal(err)
	}
}

func TestAllowUnknownToolRequiresInstanceAdmin(t *testing.T) {
	g := &Grant{Spaces: []SpaceGrant{{ID: "sp1", Level: LevelAdmin}}}
	if err := Allow(g, "ocis_brand_new_admin_tool", nil); err == nil {
		t.Fatal("unknown tools must not run without instance admin")
	}
}

func TestVisibleTools(t *testing.T) {
	g := &Grant{Spaces: []SpaceGrant{{ID: "sp1", Level: LevelRead}}}
	got := VisibleTools(g, []string{"ocis_health_check", "ocis_list_files", "ocis_upload_file", "ocis_create_user"})
	join := func(ss []string) string { return jsonDump(ss) }
	if join(got) != join([]string{"ocis_health_check", "ocis_list_files"}) {
		t.Fatalf("got %v", got)
	}
}

func jsonDump(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func TestMarshalSpaces(t *testing.T) {
	in := []SpaceGrant{{ID: "a", Name: "A", Level: LevelRead, Ceiling: LevelAdmin}}
	s, err := MarshalSpaces(in)
	if err != nil {
		t.Fatal(err)
	}
	out, err := UnmarshalSpaces(s)
	if err != nil || len(out) != 1 || out[0].ID != "a" {
		t.Fatalf("roundtrip %v %v", out, err)
	}
	empty, err := UnmarshalSpaces("")
	if err != nil || empty != nil {
		t.Fatal(err)
	}
}

func TestSpaceLevel(t *testing.T) {
	var g *Grant
	if g.SpaceLevel("x") != LevelNone {
		t.Fatal("nil grant")
	}
	g = &Grant{Spaces: []SpaceGrant{{ID: "x", Level: LevelWrite}}}
	if g.SpaceLevel("x") != LevelWrite || g.SpaceLevel("y") != LevelNone {
		t.Fatal("lookup")
	}
}
