package grant

import (
	"encoding/json"
	"fmt"
)

// Need describes what a tool requires from the Grant.
type Need struct {
	// InstanceAdmin: users/groups/roles and creating spaces for the whole server.
	// Shown as a separate "Instance administration" checkbox — never implied by
	// space admin (oCIS Manager).
	InstanceAdmin bool
	// Space: look at space_id / drive_id in the arguments.
	Space Level
	// AnySpace: tool is not tied to one id (list_my_spaces, search, notifications).
	AnySpace Level
	// Always: health, get_me, capabilities — safe for any logged-in user.
	Always bool
}

// ToolNeed is the allow-list used at tools/call time.
// Keep this in sync when new tools are registered in internal/tools.
func ToolNeed(name string) Need {
	switch name {
	case "ocis_get_me", "ocis_health_check", "ocis_get_version",
		"ocis_get_capabilities", "ocis_get_config", "ocis_get_sharing_roles":
		return Need{Always: true}

	case "ocis_list_users", "ocis_get_user", "ocis_create_user",
		"ocis_update_user", "ocis_delete_user",
		"ocis_list_groups", "ocis_get_group", "ocis_create_group",
		"ocis_update_group", "ocis_delete_group",
		"ocis_add_group_member", "ocis_remove_group_member",
		"ocis_list_roles", "ocis_assign_role", "ocis_list_assignments",
		"ocis_list_spaces", // Graph /drives — instance-wide
		"ocis_create_space", "ocis_create_project_space",
		"ocis_list_education_schools", "ocis_get_education_school",
		"ocis_list_education_users", "ocis_get_education_user",
		"ocis_create_education_user":
		return Need{InstanceAdmin: true}

	case "ocis_list_files", "ocis_get_file_info", "ocis_download_file",
		"ocis_get_file_versions", "ocis_get_resource_by_id",
		"ocis_get_resource_metadata", "ocis_get_space",
		"ocis_list_space_permissions", "ocis_get_space_overview",
		"ocis_list_shares", "ocis_list_shared_by_me", "ocis_list_received_shares":
		return Need{Space: LevelRead}

	case "ocis_create_folder", "ocis_upload_file", "ocis_move_file",
		"ocis_copy_file", "ocis_delete_file", "ocis_restore_file_version",
		"ocis_tag_resource", "ocis_untag_resource",
		"ocis_create_share", "ocis_create_link", "ocis_delete_share",
		"ocis_update_share", "ocis_update_share_expiration",
		"ocis_create_space_link", "ocis_set_space_readme",
		"ocis_upload_and_share", "ocis_share_with_link":
		return Need{Space: LevelWrite}

	case "ocis_update_space", "ocis_disable_space", "ocis_delete_space",
		"ocis_restore_space", "ocis_invite_to_space",
		"ocis_empty_trashbin", "ocis_set_space_image":
		return Need{Space: LevelAdmin}

	case "ocis_list_my_spaces", "ocis_search", "ocis_search_by_tag",
		"ocis_find_and_download", "ocis_ocm_list_providers", "ocis_ocm_list_shares",
		"ocis_ocm_list_received":
		return Need{AnySpace: LevelRead}

	case "ocis_list_notifications", "ocis_delete_notification",
		"ocis_list_app_tokens", "ocis_create_app_token", "ocis_delete_app_token",
		"ocis_ocm_create_share",
		"ocis_accept_share", "ocis_reject_share":
		return Need{AnySpace: LevelWrite}

	default:
		// Unknown tool (or a newly added admin tool we forgot to classify):
		// require instance admin so it is never accidentally exposed to a
		// read-only grant.
		return Need{InstanceAdmin: true}
	}
}

type argsEnvelope struct {
	SpaceID string `json:"space_id"`
	DriveID string `json:"drive_id"`
}

// Allow is the single enforcement function used by MCP middleware.
func Allow(g *Grant, toolName string, arguments json.RawMessage) error {
	need := ToolNeed(toolName)
	if need.Always {
		return nil
	}
	if g == nil {
		return fmt.Errorf("this session has no consent grant")
	}
	if need.InstanceAdmin {
		if !g.InstanceAdmin {
			return fmt.Errorf("tool %s requires instance administration, which was not granted", toolName)
		}
		return nil
	}
	var args argsEnvelope
	if len(arguments) > 0 {
		_ = json.Unmarshal(arguments, &args)
	}
	spaceID := args.SpaceID
	if spaceID == "" {
		spaceID = args.DriveID
	}
	if need.Space > 0 {
		if spaceID == "" {
			return fmt.Errorf("tool %s requires a space_id covered by your consent", toolName)
		}
		got := g.SpaceLevel(spaceID)
		if !got.AtLeast(need.Space) {
			return fmt.Errorf("tool %s needs %s on space %s; consent is %s",
				toolName, need.Space, spaceID, got)
		}
		return nil
	}
	if need.AnySpace > 0 {
		for _, s := range g.Spaces {
			if s.Level.AtLeast(need.AnySpace) {
				return nil
			}
		}
		return fmt.Errorf("tool %s needs at least one space granted at %s", toolName, need.AnySpace)
	}
	return fmt.Errorf("tool %s is not permitted by this grant", toolName)
}

// VisibleTools filters a tools/list result so the model never sees
// admin tools the user declined.
func VisibleTools(g *Grant, names []string) []string {
	if g == nil {
		return names
	}
	out := make([]string, 0, len(names))
	for _, n := range names {
		if err := Allow(g, n, json.RawMessage(`{}`)); err == nil {
			out = append(out, n)
			continue
		}
		// Space-scoped tools fail without an id; still show them if any
		// consented space meets the need.
		need := ToolNeed(n)
		if need.Space > 0 {
			for _, s := range g.Spaces {
				if s.Level.AtLeast(need.Space) {
					out = append(out, n)
					break
				}
			}
		}
	}
	return out
}
