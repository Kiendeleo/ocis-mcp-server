package tools

import (
	"context"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/owncloud/ocis-mcp-server/internal/grant"
)

// Common annotation helpers.
func boolPtr(b bool) *bool { return &b }

func readOnlyAnnotations() *mcp.ToolAnnotations {
	return &mcp.ToolAnnotations{
		ReadOnlyHint:    true,
		DestructiveHint: boolPtr(false),
		OpenWorldHint:   boolPtr(true),
	}
}

func mutatingAnnotations() *mcp.ToolAnnotations {
	return &mcp.ToolAnnotations{
		DestructiveHint: boolPtr(false),
		OpenWorldHint:   boolPtr(true),
	}
}

func idempotentAnnotations() *mcp.ToolAnnotations {
	return &mcp.ToolAnnotations{
		DestructiveHint: boolPtr(false),
		IdempotentHint:  true,
		OpenWorldHint:   boolPtr(true),
	}
}

func destructiveAnnotations() *mcp.ToolAnnotations {
	return &mcp.ToolAnnotations{
		DestructiveHint: boolPtr(true),
		OpenWorldHint:   boolPtr(true),
	}
}

// filterGrantedDrives drops spaces the user did not tick in the consent
// wizard. Legacy app-token / static OIDC mode has no Grant, so the list
// is returned unchanged.
func filterGrantedDrives(ctx context.Context, drives []Drive) []Drive {
	g, ok := grant.FromContext(ctx)
	if !ok || g == nil || g.InstanceAdmin {
		return drives
	}
	allowed := map[string]bool{}
	for _, s := range g.Spaces {
		allowed[s.ID] = true
	}
	out := make([]Drive, 0, len(drives))
	for _, d := range drives {
		if allowed[d.ID] {
			out = append(out, d)
		}
	}
	return out
}
