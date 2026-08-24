# OAuth 2.1 + space consent

This fork adds a **multi-user HTTP** mode so MCP clients (Claude, Cursor, …)
log in through the **same Authentik / oCIS login** the files web UI uses, then
pick which spaces the assistant may touch.

App-token and static-OIDC modes are unchanged (`stdio` still works the old way).

## What the user sees

1. The MCP client opens a browser at this server’s `/authorize`.
2. We bounce them to the **normal oCIS login** (Authentik).
3. After login, a three-step page themed from `{OCIS_URL}/themes/owncloud/theme.json`:
   - tick **personal space + every accessible space**
   - per space: **read / write / admin**, never offering a level they do not already have in oCIS (Viewer → only read, Editor → read+write, Manager → all three)
   - **Instance administration** is a separate checkbox, shown only if Graph `GET /users?$top=1` succeeds (real oCIS admin)
   - a confirmation summary, then **Allow access**
4. The MCP client receives tokens. Each tool call is checked against that grant.

Admin on a space means **oCIS Manager**. It does **not** unlock users/groups/roles.

## Security model (SOC 2–aligned practices, not a certification)

- **No token passthrough.** The MCP client never sees the oCIS access token. We store it encrypted and mint a separate MCP JWT that only names a `grant_id`.
- **AES-256-GCM** at rest for oCIS tokens and consent sessions (`OCIS_MCP_GRANT_KEY` → HKDF → column / JWT / cookie keys).
- Authorization codes and refresh tokens are **hashed** (SHA-256) before SQLite; they are single-use.
- **PKCE S256** is required (MCP client ↔ us, and us ↔ Authentik).
- Session cookie is HttpOnly + HMAC, SameSite=Lax.
- CSRF token on every consent POST.
- DCR (`POST /register`) only accepts `https://` or **http loopback** redirect URIs.
- Unknown tools default to “instance admin required”.

Rotate `OCIS_MCP_GRANT_KEY` if the database file leaks — old grants become unreadable.

## Compose: share the Authentik client with oCIS

Put one env file next to the stack. Both services interpolate the **same** values.
oCIS does not read `OCIS_MCP_*` names, so map them:

```yaml
# docker-compose snippet — see docker-compose.example.yml
services:
  ocis:
    image: owncloud/ocis:latest
    environment:
      OCIS_URL: ${OCIS_URL}
      PROXY_OIDC_ISSUER: ${OCIS_MCP_OIDC_ISSUER}
      WEB_OIDC_CLIENT_ID: ${OCIS_MCP_OIDC_CLIENT_ID}
      WEB_OIDC_CLIENT_SECRET: ${OCIS_MCP_OIDC_CLIENT_SECRET}

  ocis-mcp:
    build: .
    environment:
      OCIS_MCP_OCIS_URL: ${OCIS_URL}
      OCIS_MCP_AUTH_MODE: oauth
      OCIS_MCP_TRANSPORT: http
      OCIS_MCP_HTTP_ADDR: "0.0.0.0:8090"
      OCIS_MCP_PUBLIC_URL: ${OCIS_MCP_PUBLIC_URL}
      OCIS_MCP_OIDC_ISSUER: ${OCIS_MCP_OIDC_ISSUER}   # optional; default = OCIS_URL
      OCIS_MCP_OIDC_CLIENT_ID: ${OCIS_MCP_OIDC_CLIENT_ID}
      OCIS_MCP_OIDC_CLIENT_SECRET: ${OCIS_MCP_OIDC_CLIENT_SECRET}
      OCIS_MCP_GRANT_KEY: ${OCIS_MCP_GRANT_KEY}
      OCIS_MCP_GRANT_DB: /var/lib/ocis-mcp/grants.db
    volumes:
      - mcp-grants:/var/lib/ocis-mcp
    ports:
      - "8090:8090"
```

```bash
# generate once, keep in the same .env oCIS already uses
openssl rand -hex 32   # → OCIS_MCP_GRANT_KEY
```

### Authentik application

Use the **existing oCIS application**. Add one redirect URI:

```
{OCIS_MCP_PUBLIC_URL}/oauth/callback
```

Example: `https://mcp.example.com/oauth/callback`.

Leave the original oCIS callback in place. PKCE and `offline_access` should be allowed (Authentik defaults).

## MCP client

Point the client at `https://mcp.example.com/mcp` (or whatever `OCIS_MCP_PUBLIC_URL` is, plus `/mcp`).

Modern clients discover:

- `/.well-known/oauth-protected-resource`
- `/.well-known/oauth-authorization-server`
- `POST /register` (dynamic client registration)

No shared `OCIS_MCP_HTTP_SECRET` in this mode — each user has their own grant.

## Env vars (oauth mode)

| Variable | Required | Notes |
|---|---|---|
| `OCIS_MCP_OCIS_URL` | yes | Files instance, e.g. `https://cloud.example.com` |
| `OCIS_MCP_AUTH_MODE` | yes | `oauth` |
| `OCIS_MCP_TRANSPORT` | yes | `http` |
| `OCIS_MCP_PUBLIC_URL` | yes | URL browsers and MCP clients open |
| `OCIS_MCP_OIDC_CLIENT_ID` | yes | Same Authentik client as oCIS |
| `OCIS_MCP_OIDC_CLIENT_SECRET` | if confidential | Same secret as oCIS |
| `OCIS_MCP_OIDC_ISSUER` | no | Default: `OCIS_MCP_OCIS_URL` (oCIS proxies discovery) |
| `OCIS_MCP_GRANT_KEY` | yes | 32-byte hex (`openssl rand -hex 32`) |
| `OCIS_MCP_GRANT_DB` | no | Default `data/grants.db`; image uses `/var/lib/ocis-mcp/grants.db` |
| `OCIS_MCP_HTTP_ADDR` | no | Docker: `0.0.0.0:8090` |

`OCIS_MCP_HTTP_SECRET` is **not** used in oauth mode.

## Reuse (Ansible / many customers)

One image, one compose snippet, per-customer env:

- `OCIS_URL` / `OCIS_MCP_PUBLIC_URL`
- Authentik client id/secret (already on the oCIS stack)
- `OCIS_MCP_GRANT_KEY` unique per customer
- extra Authentik redirect URI for that customer’s MCP public URL
