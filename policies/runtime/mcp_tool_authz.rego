package assurance.runtime.mcp_tool_authz

import rego.v1

# Runtime Policy Decision Point (PDP) for MCP 2026-07-28 Tool Invocations
# Enforces NIST AC-3 (Access Enforcement), AC-6(10) (Privileged/Destructive Guard), and CM-7.

default allow := false

# Tier 1: Read-only tools allowed for triage, responder, and commander profiles
allow if {
	input.tool.annotations.readOnlyHint == true
	input.tool.annotations.destructiveHint == false
	input.caller.role in {"incident-triage-readonly", "incident-responder", "incident-commander"}
}

# Tier 2: Non-destructive mutating tools (POST/PUT) allowed for responder and commander roles
allow if {
	input.tool.annotations.readOnlyHint == false
	input.tool.annotations.destructiveHint == false
	input.caller.role in {"incident-responder", "incident-commander"}
}

# Tier 3: Destructive tools (DELETE / destructiveHint == true) require commander role + valid break-glass ticket
allow if {
	input.tool.annotations.destructiveHint == true
	input.caller.role == "incident-commander"
	startswith(input.caller.elevation_ticket, "INC-BREAKGLASS-")
}

deny_reason contains msg if {
	input.tool.annotations.destructiveHint == true
	input.caller.role != "incident-commander"
	msg := sprintf(
		"AC-6(10) deny: role '%s' cannot execute destructive tool '%s'",
		[input.caller.role, input.tool.name],
	)
}

deny_reason contains msg if {
	input.tool.annotations.destructiveHint == true
	input.caller.role == "incident-commander"
	not startswith(object.get(input.caller, "elevation_ticket", ""), "INC-BREAKGLASS-")
	msg := sprintf(
		"AC-6(10) deny: destructive tool '%s' requires INC-BREAKGLASS-* elevation_ticket",
		[input.tool.name],
	)
}
