package store

import (
	"bytes"
	"path/filepath"
	"testing"
	"time"

	"github.com/owncloud/ocis-mcp-server/internal/grant"
	"github.com/owncloud/ocis-mcp-server/internal/secretbox"
)

func testStore(t *testing.T) *Store {
	t.Helper()
	key := bytes.Repeat([]byte{0x42}, 32)
	st, err := Open(filepath.Join(t.TempDir(), "grants.db"), key)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

func TestClientRoundTrip(t *testing.T) {
	st := testStore(t)
	c := Client{ID: "mcp-abc", Name: "Claude", RedirectURIs: []string{"http://127.0.0.1:9/cb"}}
	if err := st.PutClient(c); err != nil {
		t.Fatal(err)
	}
	got, err := st.GetClient("mcp-abc")
	if err != nil {
		t.Fatal(err)
	}
	if got.Name != "Claude" || !got.ValidRedirect("http://127.0.0.1:9/cb") || got.ValidRedirect("https://evil.example/cb") {
		t.Fatalf("%+v", got)
	}
}

func TestSessionEncryptAndExpire(t *testing.T) {
	st := testStore(t)
	if err := st.PutSession("s1", []byte(`{"hello":"secret-token"}`), time.Hour); err != nil {
		t.Fatal(err)
	}
	got, err := st.GetSession("s1")
	if err != nil || string(got) != `{"hello":"secret-token"}` {
		t.Fatalf("%q %v", got, err)
	}
	st.DeleteSession("s1")
	if _, err := st.GetSession("s1"); err == nil {
		t.Fatal("deleted")
	}
}

func TestGrantTokensEncryptedAtRest(t *testing.T) {
	st := testStore(t)
	g := &grant.Grant{
		ID: "g1", UserID: "u1", UserName: "Ada", ClientID: "c1",
		Spaces:         []grant.SpaceGrant{{ID: "sp", Name: "Personal", Level: grant.LevelRead, Ceiling: grant.LevelAdmin}},
		OcisAccess:     "super-secret-access",
		OcisRefresh:    "super-secret-refresh",
		OcisExpiryUnix: time.Now().Add(time.Hour).Unix(),
	}
	if err := st.PutGrant(g); err != nil {
		t.Fatal(err)
	}
	got, err := st.GetGrant("g1")
	if err != nil {
		t.Fatal(err)
	}
	if got.OcisAccess != g.OcisAccess || got.UserName != "Ada" {
		t.Fatalf("%+v", got)
	}

	var blob []byte
	if err := st.db.QueryRow(`SELECT ocis_token_enc FROM grants WHERE id=?`, "g1").Scan(&blob); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(blob, []byte("super-secret")) {
		t.Fatal("plaintext token leaked into sqlite")
	}
	if _, err := secretbox.Open(bytes.Repeat([]byte{0x00}, 32), blob); err == nil {
		t.Fatal("wrong key must not decrypt")
	}
}

func TestAuthCodeSingleUse(t *testing.T) {
	st := testStore(t)
	if err := st.PutAuthCode("the-code", "g1", "c1", "http://127.0.0.1/cb", "challenge", time.Minute); err != nil {
		t.Fatal(err)
	}
	gid, cid, redir, ch, err := st.ConsumeAuthCode("the-code")
	if err != nil || gid != "g1" || cid != "c1" || redir != "http://127.0.0.1/cb" || ch != "challenge" {
		t.Fatalf("%s %s %s %s %v", gid, cid, redir, ch, err)
	}
	if _, _, _, _, err := st.ConsumeAuthCode("the-code"); err == nil {
		t.Fatal("reuse must fail")
	}
}

func TestRefreshConsumeAndRevokeGrant(t *testing.T) {
	st := testStore(t)
	g := &grant.Grant{ID: "g2", UserID: "u", ClientID: "c"}
	if err := st.PutGrant(g); err != nil {
		t.Fatal(err)
	}
	if err := st.PutRefresh("rt", "g2", "c", time.Hour); err != nil {
		t.Fatal(err)
	}
	gid, cid, err := st.ConsumeRefresh("rt")
	if err != nil || gid != "g2" || cid != "c" {
		t.Fatal(err)
	}
	if _, _, err := st.ConsumeRefresh("rt"); err == nil {
		t.Fatal("refresh reuse")
	}
	if err := st.RevokeGrant("g2"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.GetGrant("g2"); err == nil {
		t.Fatal("revoked grant still readable")
	}
}

func TestHashTokenStable(t *testing.T) {
	if HashToken("a") == HashToken("b") || len(HashToken("a")) != 64 {
		t.Fatal("sha256 hex")
	}
}
