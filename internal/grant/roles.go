package grant

import "strings"

// MapOcisRole converts an oCIS / LibreGraph role name or id into a Level.
//
// oCIS spaces typically use Viewer / Editor / Manager. We also recognise
// a few LibreGraph unified-role aliases so a theme or version bump does
// not silently drop people to "read".
func MapOcisRole(role string) Level {
	r := strings.ToLower(strings.TrimSpace(role))
	r = strings.TrimPrefix(r, "sp.")
	r = strings.ReplaceAll(r, " ", "")
	switch {
	case r == "":
		return LevelNone
	case strings.Contains(r, "manager"),
		strings.Contains(r, "admin"),
		strings.Contains(r, "owner"),
		r == "spaceadmin":
		return LevelAdmin
	case strings.Contains(r, "editor"),
		strings.Contains(r, "writer"),
		strings.Contains(r, "contributor"),
		r == "edit",
		r == "uploader":
		return LevelWrite
	case strings.Contains(r, "viewer"),
		strings.Contains(r, "reader"),
		strings.Contains(r, "guest"),
		r == "view",
		r == "read":
		return LevelRead
	default:
		// Unknown UUID: treat as "they can see the space" (read), never
		// invent write/admin. The wizard will not offer stronger levels.
		return LevelRead
	}
}

// CeilingFromRoles is the strongest role in the list.
func CeilingFromRoles(roles []string) Level {
	max := LevelNone
	for _, r := range roles {
		if l := MapOcisRole(r); l > max {
			max = l
		}
	}
	return max
}

// ClampLevel never lets a consent choice exceed the user's real oCIS role.
func ClampLevel(want, ceiling Level) Level {
	if want > ceiling {
		return ceiling
	}
	if want < LevelRead {
		return LevelNone
	}
	return want
}

// LevelsOffered is the radio-button list for one space.
func LevelsOffered(ceiling Level) []Level {
	var out []Level
	if ceiling >= LevelRead {
		out = append(out, LevelRead)
	}
	if ceiling >= LevelWrite {
		out = append(out, LevelWrite)
	}
	if ceiling >= LevelAdmin {
		out = append(out, LevelAdmin)
	}
	return out
}
