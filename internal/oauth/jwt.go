package oauth

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// AccessClaims is the MCP access token. It names the grant; space ACLs
// live in SQLite so they can be revoked independently of token expiry.
type AccessClaims struct {
	GrantID  string `json:"gid"`
	ClientID string `json:"cid"`
	jwt.RegisteredClaims
}

func SignAccess(hmacKey []byte, issuer, audience, subject, grantID, clientID string, ttl time.Duration) (string, error) {
	now := time.Now()
	t := jwt.NewWithClaims(jwt.SigningMethodHS256, AccessClaims{
		GrantID:  grantID,
		ClientID: clientID,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    issuer,
			Subject:   subject,
			Audience:  jwt.ClaimStrings{audience},
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
			NotBefore: jwt.NewNumericDate(now.Add(-30 * time.Second)),
			ID:        randomNonce(),
		},
	})
	return t.SignedString(hmacKey)
}

func ParseAccess(hmacKey []byte, issuer, audience, raw string) (*AccessClaims, error) {
	tok, err := jwt.ParseWithClaims(raw, &AccessClaims{}, func(t *jwt.Token) (any, error) {
		if t.Method != jwt.SigningMethodHS256 {
			return nil, fmt.Errorf("unexpected signing method")
		}
		return hmacKey, nil
	}, jwt.WithIssuer(issuer), jwt.WithAudience(audience), jwt.WithLeeway(30*time.Second))
	if err != nil {
		return nil, err
	}
	c, ok := tok.Claims.(*AccessClaims)
	if !ok || !tok.Valid {
		return nil, fmt.Errorf("invalid access token")
	}
	if c.GrantID == "" {
		return nil, fmt.Errorf("token missing grant id")
	}
	return c, nil
}
