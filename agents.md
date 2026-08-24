# agents.md -- oCIS MCP Server (Kiendeleo fork)

## Repository Overview

Fork of [owncloud/ocis-mcp-server](https://github.com/owncloud/ocis-mcp-server).
Standalone MCP server for oCIS, written in Go. This fork adds **OAuth 2.1**
(RFC 9728 resource metadata, PKCE S256, RFC 7591 DCR) and a **space-level
consent wizard** so one process can serve many users against Authentik as
oCIS’s IdP.

Keep the Go module path `github.com/owncloud/ocis-mcp-server` so rebases onto
`upstream/main` stay mechanical.

Apache-2.0. Licensed files are covered by root `REUSE.toml`.

## Architecture & Key Paths

Upstream (unchanged unless noted):

- `internal/tools/` -- 80+ MCP tools (LibreGraph, WebDAV, OCS)
- `internal/client/` -- oCIS HTTP client. **Fork:** `applyAuth` prefers a
  per-request grant token (`internal/client/authctx.go`) over the process
  app-token / static OIDC credential
- `internal/config/` -- env config. **Fork:** `AUTH_MODE=oauth`
- `cmd/ocis-mcp-server/main.go` -- stdio still uses the SDK runner; HTTP
  goes through `internal/httpapi`

Fork-only packages (do not exist upstream — keep them self-contained for rebase):

| Package | Role |
|---|---|
| `internal/oauth` | AS metadata, DCR, token, PKCE, MCP JWTs |
| `internal/oidc` | Discover Authentik via oCIS, list spaces, admin probe |
| `internal/consent` | 3-step themed HTML wizard |
| `internal/grant` | Space read/write/admin + instance-admin allow-list |
| `internal/store` | Encrypted SQLite (AES-256-GCM) |
| `internal/secretbox` | HKDF + AES-GCM |
| `internal/theme` | `{ocis}/themes/owncloud/theme.json` |
| `internal/httpapi` | One listener: well-known + consent + `/mcp` |

Operator docs: [`OAUTH.md`](OAUTH.md), [`docker-compose.example.yml`](docker-compose.example.yml).

## Consent rules (do not relax)

- Login **is** oCIS/Authentik. Never a second password form.
- Checklist: personal space first, then every accessible space.
- Per space: read / write / admin. **Clamp to the user’s real oCIS role.**
  Admin on a space = oCIS **Manager**.
- Instance-wide tools (users, groups, roles, `ocis_list_spaces`, create space)
  need oCIS admin **and** a separate “Instance administration” checkbox.
- No extra knobs on the wizard.

## Development Conventions

- Go, CGO-free (`modernc.org/sqlite`) so `CGO_ENABLED=0` Docker builds keep working
- MCP protocol (stdio / Streamable HTTP)
- No oCIS Go imports — public APIs only
- Novice-readable comments on security-sensitive code (keys, grants, PKCE)
- Preserve upstream tool handlers; enforce grants in middleware +
  `filterGrantedDrives` for list results

## Extra dependencies (this fork)

Approved; **do not** apply upstream OSPO “open an issue first” for these:

- `golang.org/x/oauth2` (already transitive; used as a direct import)
- `github.com/golang-jwt/jwt/v5`
- `golang.org/x/crypto` (HKDF)
- `modernc.org/sqlite`

New dependencies beyond this list: discuss in a PR description first.

## Build & Test Commands

```bash
make build                    # Build the binary
make test                     # go test -race ./...
make lint                     # golangci-lint
make cover                    # Coverage report (CI threshold 70%)
make docker-build
```

OAuth mode needs no live oCIS for unit tests; handlers use `httptest` and a temp SQLite file.

## Git workflow (this fork)

- Branch for review: `feat/oauth21-consent` → `main` on **this** repo
- Rebase onto `upstream/main`; never merge-commit if we later send code back
- DCO sign-off (`git commit -s`) when committing locally
- GPG-signed commits are preferred but **not required** on this fork
  (GitHub-connector / API pushes cannot sign)
- Conventional Commit PR titles (`feat:`, `fix:`, `docs:`)

## OSPO notes

Upstream OSPO rules (pin `actions/*` SHAs, no unverified Actions) still apply
if we touch `.github/workflows`. The “issue first for every new dependency”
rule is **waived here** — this is a product fork, not the ownCloud org repo.

## Context for AI Agents

When adding a tool in `internal/tools`, also classify it in
`internal/grant/catalog.go` (`ToolNeed`). Unknown names default to
instance-admin so they cannot leak through a read-only grant.
