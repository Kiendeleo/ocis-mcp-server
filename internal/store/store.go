// Package store is the SQLite grant/session database.
//
// Sensitive columns (oCIS tokens, session JSON) are AES-256-GCM encrypted
// with a key derived from OCIS_MCP_GRANT_KEY. Hashes of authorization codes
// and refresh tokens are stored, never the raw values, so a stolen DB cannot
// be used to mint sessions without the GRANT_KEY and the token itself.
package store

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/owncloud/ocis-mcp-server/internal/grant"
	"github.com/owncloud/ocis-mcp-server/internal/secretbox"

	_ "modernc.org/sqlite" // pure-Go driver; keeps CGO_ENABLED=0 Docker builds working
)

// Store is safe for concurrent use.
type Store struct {
	db      *sql.DB
	colKey  []byte
	mu      sync.Mutex
}

func Open(path string, columnKey []byte) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil && filepath.Dir(path) != "." && filepath.Dir(path) != "" {
		return nil, fmt.Errorf("creating db dir: %w", err)
	}
	db, err := sql.Open("sqlite", path+"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)")
	if err != nil {
		return nil, err
	}
	s := &Store{db: db, colKey: columnKey}
	if err := s.migrate(); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) migrate() error {
	_, err := s.db.Exec(`
CREATE TABLE IF NOT EXISTS oauth_clients (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  secret_hash TEXT,
  redirect_uris TEXT NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
  id TEXT PRIMARY KEY,
  data_enc BLOB NOT NULL,
  expires_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS grants (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  user_name TEXT,
  client_id TEXT NOT NULL,
  spaces_json TEXT NOT NULL,
  instance_admin INTEGER NOT NULL DEFAULT 0,
  ocis_token_enc BLOB,
  created_at INTEGER NOT NULL,
  revoked_at INTEGER
);
CREATE TABLE IF NOT EXISTS auth_codes (
  code_hash TEXT PRIMARY KEY,
  grant_id TEXT NOT NULL,
  client_id TEXT NOT NULL,
  redirect_uri TEXT NOT NULL,
  code_challenge TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  used INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS refresh_tokens (
  token_hash TEXT PRIMARY KEY,
  grant_id TEXT NOT NULL,
  client_id TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  revoked INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS audit (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  at INTEGER NOT NULL,
  event TEXT NOT NULL,
  user_id TEXT,
  client_id TEXT,
  detail TEXT
);
CREATE INDEX IF NOT EXISTS idx_sessions_exp ON sessions(expires_at);
CREATE INDEX IF NOT EXISTS idx_grants_user ON grants(user_id);
`)
	return err
}

func RandomID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func HashToken(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

func (s *Store) Audit(event, userID, clientID, detail string) {
	_, _ = s.db.Exec(`INSERT INTO audit(at,event,user_id,client_id,detail) VALUES(?,?,?,?,?)`,
		time.Now().Unix(), event, userID, clientID, detail)
}

// ----- clients (Dynamic Client Registration) -----

type Client struct {
	ID           string
	Name         string
	SecretHash   string
	RedirectURIs []string
}

func (s *Store) PutClient(c Client) error {
	uris, _ := json.Marshal(c.RedirectURIs)
	_, err := s.db.Exec(`INSERT OR REPLACE INTO oauth_clients(id,name,secret_hash,redirect_uris,created_at) VALUES(?,?,?,?,?)`,
		c.ID, c.Name, c.SecretHash, string(uris), time.Now().Unix())
	return err
}

func (s *Store) GetClient(id string) (Client, error) {
	var c Client
	var uris string
	err := s.db.QueryRow(`SELECT id,name,secret_hash,redirect_uris FROM oauth_clients WHERE id=?`, id).
		Scan(&c.ID, &c.Name, &c.SecretHash, &uris)
	if err != nil {
		return c, err
	}
	_ = json.Unmarshal([]byte(uris), &c.RedirectURIs)
	return c, nil
}

func (c Client) ValidRedirect(uri string) bool {
	for _, u := range c.RedirectURIs {
		if u == uri {
			return true
		}
	}
	return false
}

// ----- encrypted sessions (consent wizard) -----

func (s *Store) PutSession(id string, payload []byte, ttl time.Duration) error {
	enc, err := secretbox.Seal(s.colKey, payload)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`INSERT OR REPLACE INTO sessions(id,data_enc,expires_at) VALUES(?,?,?)`,
		id, enc, time.Now().Add(ttl).Unix())
	return err
}

func (s *Store) GetSession(id string) ([]byte, error) {
	var enc []byte
	var exp int64
	err := s.db.QueryRow(`SELECT data_enc,expires_at FROM sessions WHERE id=?`, id).Scan(&enc, &exp)
	if err != nil {
		return nil, err
	}
	if time.Now().Unix() > exp {
		_, _ = s.db.Exec(`DELETE FROM sessions WHERE id=?`, id)
		return nil, fmt.Errorf("session expired")
	}
	return secretbox.Open(s.colKey, enc)
}

func (s *Store) DeleteSession(id string) {
	_, _ = s.db.Exec(`DELETE FROM sessions WHERE id=?`, id)
}

// ----- grants -----

type ocisTok struct {
	Access  string `json:"a"`
	Refresh string `json:"r"`
	Expiry  int64  `json:"e"`
}

func (s *Store) PutGrant(g *grant.Grant) error {
	spaces, err := grant.MarshalSpaces(g.Spaces)
	if err != nil {
		return err
	}
	tok, _ := json.Marshal(ocisTok{Access: g.OcisAccess, Refresh: g.OcisRefresh, Expiry: g.OcisExpiryUnix})
	enc, err := secretbox.Seal(s.colKey, tok)
	if err != nil {
		return err
	}
	admin := 0
	if g.InstanceAdmin {
		admin = 1
	}
	_, err = s.db.Exec(`INSERT OR REPLACE INTO grants(id,user_id,user_name,client_id,spaces_json,instance_admin,ocis_token_enc,created_at) VALUES(?,?,?,?,?,?,?,?)`,
		g.ID, g.UserID, g.UserName, g.ClientID, spaces, admin, enc, time.Now().Unix())
	return err
}

func (s *Store) GetGrant(id string) (*grant.Grant, error) {
	var g grant.Grant
	var spaces string
	var admin int
	var enc []byte
	var revoked sql.NullInt64
	err := s.db.QueryRow(`SELECT id,user_id,user_name,client_id,spaces_json,instance_admin,ocis_token_enc,revoked_at FROM grants WHERE id=?`, id).
		Scan(&g.ID, &g.UserID, &g.UserName, &g.ClientID, &spaces, &admin, &enc, &revoked)
	if err != nil {
		return nil, err
	}
	if revoked.Valid && revoked.Int64 > 0 {
		return nil, fmt.Errorf("grant revoked")
	}
	g.InstanceAdmin = admin == 1
	g.Spaces, err = grant.UnmarshalSpaces(spaces)
	if err != nil {
		return nil, err
	}
	raw, err := secretbox.Open(s.colKey, enc)
	if err != nil {
		return nil, err
	}
	var tok ocisTok
	if err := json.Unmarshal(raw, &tok); err != nil {
		return nil, err
	}
	g.OcisAccess, g.OcisRefresh, g.OcisExpiryUnix = tok.Access, tok.Refresh, tok.Expiry
	return &g, nil
}

func (s *Store) UpdateOcisTokens(grantID, access, refresh string, expiryUnix int64) error {
	g, err := s.GetGrant(grantID)
	if err != nil {
		return err
	}
	g.OcisAccess, g.OcisRefresh, g.OcisExpiryUnix = access, refresh, expiryUnix
	return s.PutGrant(g)
}

func (s *Store) RevokeGrant(id string) error {
	_, err := s.db.Exec(`UPDATE grants SET revoked_at=? WHERE id=?`, time.Now().Unix(), id)
	return err
}

// ----- codes & refresh tokens -----

func (s *Store) PutAuthCode(rawCode, grantID, clientID, redirect, challenge string, ttl time.Duration) error {
	_, err := s.db.Exec(`INSERT INTO auth_codes(code_hash,grant_id,client_id,redirect_uri,code_challenge,expires_at) VALUES(?,?,?,?,?,?)`,
		HashToken(rawCode), grantID, clientID, redirect, challenge, time.Now().Add(ttl).Unix())
	return err
}

func (s *Store) ConsumeAuthCode(rawCode string) (grantID, clientID, redirect, challenge string, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	h := HashToken(rawCode)
	var exp int64
	var used int
	err = s.db.QueryRow(`SELECT grant_id,client_id,redirect_uri,code_challenge,expires_at,used FROM auth_codes WHERE code_hash=?`, h).
		Scan(&grantID, &clientID, &redirect, &challenge, &exp, &used)
	if err != nil {
		return "", "", "", "", fmt.Errorf("invalid authorization code")
	}
	if used != 0 || time.Now().Unix() > exp {
		return "", "", "", "", fmt.Errorf("authorization code expired or reused")
	}
	_, _ = s.db.Exec(`UPDATE auth_codes SET used=1 WHERE code_hash=?`, h)
	return grantID, clientID, redirect, challenge, nil
}

func (s *Store) PutRefresh(raw, grantID, clientID string, ttl time.Duration) error {
	_, err := s.db.Exec(`INSERT INTO refresh_tokens(token_hash,grant_id,client_id,expires_at) VALUES(?,?,?,?)`,
		HashToken(raw), grantID, clientID, time.Now().Add(ttl).Unix())
	return err
}

func (s *Store) ConsumeRefresh(raw string) (grantID, clientID string, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	h := HashToken(raw)
	var exp int64
	var revoked int
	err = s.db.QueryRow(`SELECT grant_id,client_id,expires_at,revoked FROM refresh_tokens WHERE token_hash=?`, h).
		Scan(&grantID, &clientID, &exp, &revoked)
	if err != nil {
		return "", "", fmt.Errorf("invalid refresh token")
	}
	if revoked != 0 || time.Now().Unix() > exp {
		return "", "", fmt.Errorf("refresh token expired or revoked")
	}
	_, _ = s.db.Exec(`UPDATE refresh_tokens SET revoked=1 WHERE token_hash=?`, h)
	return grantID, clientID, nil
}
