package consent

import (
	"fmt"
	"html"
	"strings"

	"github.com/owncloud/ocis-mcp-server/internal/grant"
	"github.com/owncloud/ocis-mcp-server/internal/theme"
)

func page(th theme.Theme, title, step, inner string) string {
	logo := ""
	if th.LogoURL != "" {
		logo = fmt.Sprintf(`<img class="logo" src="%s" alt="%s">`, html.EscapeString(th.LogoURL), html.EscapeString(th.Name))
	}
	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>%s · %s</title>
<style>
%s
* { box-sizing: border-box; }
body { margin:0; font-family: "Source Sans Pro", "Inter", system-ui, sans-serif; background: var(--oc-bg); color:#1a1a1a; }
.top { background: var(--oc-brand); color: var(--oc-contrast); padding: 0.75rem 1.5rem; display:flex; align-items:center; gap:0.75rem; }
.logo { height: 32px; }
main { max-width: 640px; margin: 2rem auto; background:#fff; border-radius: 8px; box-shadow: 0 8px 24px rgba(4,30,66,.12); padding: 2rem; }
h1 { font-size: 1.35rem; margin: 0 0 0.25rem; color: var(--oc-brand); }
.sub { color:#4c5f79; margin-bottom: 1.5rem; }
.steps { display:flex; gap:0.5rem; margin-bottom:1.5rem; font-size:0.8rem; text-transform:uppercase; letter-spacing:.04em; }
.steps span { flex:1; text-align:center; padding:0.4rem; border-bottom: 3px solid #d8dee8; color:#6b7c93; }
.steps span.on { border-color: var(--oc-brand); color: var(--oc-brand); font-weight:600; }
label.row { display:flex; gap:0.75rem; align-items:flex-start; padding:0.85rem 0; border-bottom:1px solid #eef1f5; }
label.row:last-of-type { border-bottom:none; }
.name { font-weight:600; }
.meta { font-size:0.85rem; color:#4c5f79; }
.levels { display:flex; gap:1rem; margin:0.4rem 0 0 1.7rem; }
button, .btn { background: var(--oc-brand); color: var(--oc-contrast); border:0; border-radius:4px; padding:0.7rem 1.2rem; font-size:1rem; cursor:pointer; }
button:hover { background: var(--oc-brand-hover); }
.secondary { background:#fff; color: var(--oc-brand); border:1px solid var(--oc-brand); }
.actions { display:flex; justify-content:space-between; margin-top:1.5rem; }
ul.summary { padding-left: 1.2rem; }
.warn { background:#fff6e5; border-left:4px solid #e6a817; padding:0.75rem 1rem; margin:1rem 0; }
</style>
</head>
<body>
<header class="top">%s<strong>%s</strong></header>
<main>
<div class="steps">
  <span class="%s">1 · Spaces</span>
  <span class="%s">2 · Access</span>
  <span class="%s">3 · Confirm</span>
</div>
%s
</main>
</body></html>`,
		html.EscapeString(title), html.EscapeString(th.Name),
		th.CSS(), logo, html.EscapeString(th.Name),
		on(step, "spaces"), on(step, "levels"), on(step, "confirm"),
		inner)
}

func on(cur, want string) string {
	if cur == want {
		return "on"
	}
	return ""
}

func SpacesPage(th theme.Theme, csrf string, spaces []grant.SpaceGrant, selected map[string]bool) string {
	var b strings.Builder
	b.WriteString(`<h1>Choose spaces</h1><p class="sub">The application will only see the spaces you tick. Your personal space is listed first.</p>`)
	b.WriteString(`<form method="post" action="/consent/spaces">`)
	b.WriteString(`<input type="hidden" name="csrf" value="` + html.EscapeString(csrf) + `">`)
	for _, s := range spaces {
		checked := ""
		if selected[s.ID] {
			checked = " checked"
		}
		kind := s.DriveType
		if kind == "personal" {
			kind = "Personal space"
		}
		fmt.Fprintf(&b, `<label class="row"><input type="checkbox" name="space" value="%s"%s>
<div><div class="name">%s</div><div class="meta">%s · your access: %s</div></div></label>`,
			html.EscapeString(s.ID), checked,
			html.EscapeString(s.Name),
			html.EscapeString(kind),
			html.EscapeString(s.Ceiling.String()))
	}
	b.WriteString(`<div class="actions"><span></span><button type="submit">Continue</button></div></form>`)
	return page(th, "Choose spaces", "spaces", b.String())
}

func LevelsPage(th theme.Theme, csrf string, spaces []grant.SpaceGrant, instOK, wantInst bool) string {
	var b strings.Builder
	b.WriteString(`<h1>Access for each space</h1><p class="sub">You can only grant what you already have in ownCloud. Viewer spaces cannot be raised to write or admin.</p>`)
	b.WriteString(`<form method="post" action="/consent/levels">`)
	b.WriteString(`<input type="hidden" name="csrf" value="` + html.EscapeString(csrf) + `">`)
	for _, s := range spaces {
		fmt.Fprintf(&b, `<div class="row"><div class="name">%s</div><div class="meta">ceiling: %s</div><div class="levels">`,
			html.EscapeString(s.Name), html.EscapeString(s.Ceiling.String()))
		for _, lv := range grant.LevelsOffered(s.Ceiling) {
			ck := ""
			if s.Level == lv || (s.Level == grant.LevelNone && lv == grant.LevelRead) {
				ck = " checked"
			}
			fmt.Fprintf(&b, `<label><input type="radio" name="level_%s" value="%s"%s> %s</label>`,
				html.EscapeString(s.ID), lv.String(), ck, lv.String())
		}
		b.WriteString(`</div></div>`)
	}
	if instOK {
		ck := ""
		if wantInst {
			ck = " checked"
		}
		fmt.Fprintf(&b, `<label class="row"><input type="checkbox" name="instance_admin" value="1"%s>
<div><div class="name">Instance administration</div>
<div class="meta">Users, groups, roles, and creating spaces for the whole server. Only shown because your account is an oCIS admin.</div></div></label>`, ck)
	}
	b.WriteString(`<div class="actions"><a class="btn secondary" href="/consent/spaces">Back</a><button type="submit">Continue</button></div></form>`)
	return page(th, "Access level", "levels", b.String())
}

func ConfirmPage(th theme.Theme, csrf, clientName string, spaces []grant.SpaceGrant, inst bool) string {
	var b strings.Builder
	fmt.Fprintf(&b, `<h1>Confirm access</h1><p class="sub"><strong>%s</strong> will be allowed to act as you, limited to the following.</p>`, html.EscapeString(clientName))
	b.WriteString(`<ul class="summary">`)
	for _, s := range spaces {
		fmt.Fprintf(&b, `<li><strong>%s</strong> — %s</li>`, html.EscapeString(s.Name), html.EscapeString(s.Level.String()))
	}
	if inst {
		b.WriteString(`<li><strong>Instance administration</strong> — users, groups, roles</li>`)
	}
	b.WriteString(`</ul>`)
	b.WriteString(`<p class="warn">You can disconnect this application later by revoking its grant (restart the MCP server with a new GRANT_KEY, or delete the grant row). Tokens expire automatically.</p>`)
	b.WriteString(`<form method="post" action="/consent/confirm">`)
	b.WriteString(`<input type="hidden" name="csrf" value="` + html.EscapeString(csrf) + `">`)
	b.WriteString(`<div class="actions"><a class="btn secondary" href="/consent/levels">Back</a><button type="submit">Allow access</button></div></form>`)
	return page(th, "Confirm", "confirm", b.String())
}

func ErrorPage(th theme.Theme, msg string) string {
	inner := `<h1>Could not continue</h1><p class="sub">` + html.EscapeString(msg) + `</p>`
	return page(th, "Error", "spaces", inner)
}
