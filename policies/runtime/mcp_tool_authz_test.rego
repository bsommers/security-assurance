package assurance.runtime.mcp_tool_authz_test

import rego.v1

import data.assurance.runtime.mcp_tool_authz

get_tool := {
	"name": "get_incident",
	"annotations": {"readOnlyHint": true, "destructiveHint": false},
}

update_tool := {
	"name": "update_incident_status",
	"annotations": {"readOnlyHint": false, "destructiveHint": false},
}

delete_tool := {
	"name": "delete_incident",
	"annotations": {"readOnlyHint": false, "destructiveHint": true},
}

test_readonly_agent_can_read_but_not_mutate_or_delete if {
	mcp_tool_authz.allow with input as {"caller": {"role": "incident-triage-readonly"}, "tool": get_tool}
	not mcp_tool_authz.allow with input as {"caller": {"role": "incident-triage-readonly"}, "tool": update_tool}
	not mcp_tool_authz.allow with input as {"caller": {"role": "incident-triage-readonly"}, "tool": delete_tool}
}

test_responder_can_update_but_not_delete if {
	mcp_tool_authz.allow with input as {"caller": {"role": "incident-responder"}, "tool": update_tool}
	not mcp_tool_authz.allow with input as {"caller": {"role": "incident-responder"}, "tool": delete_tool}
}

test_commander_requires_breakglass_ticket_for_delete if {
	not mcp_tool_authz.allow with input as {
		"caller": {"role": "incident-commander", "elevation_ticket": ""},
		"tool": delete_tool,
	}
	mcp_tool_authz.allow with input as {
		"caller": {"role": "incident-commander", "elevation_ticket": "INC-BREAKGLASS-9042"},
		"tool": delete_tool,
	}
}
