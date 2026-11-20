package assurance.forge.manifest_guard

import rego.v1

max_tools_per_profile := 15

max_response_bytes_cap := 32768

max_timeout_seconds := 30.0

allowed_auth_types := {"bearer", "api_key_header", "api_key_query", "basic", "oauth2_client_credentials"}

default allow := false

allow if {
	count(deny) == 0
}

# MCP 2026-07-28 Protocol Version Enforcement (SEP-2575)
deny contains msg if {
	input.manifest.protocol_revision != "2026-07-28"
	msg := sprintf(
		"Protocol violation: expected protocol_revision '2026-07-28', got '%v'",
		[input.manifest.protocol_revision],
	)
}

# NIST CM-7 / Pattern MCP-005: Active Toolset Budget <= 15
deny contains msg if {
	tool_count := count(input.manifest.tools)
	tool_count > max_tools_per_profile
	msg := sprintf(
		"CM-7 / MCP-005 violation: manifest defines %d tools (max allowed is %d)",
		[tool_count, max_tools_per_profile],
	)
}

# NIST AC-6 / Pattern MCP-001: Server-Bound Auth Required (No Client Passthrough)
deny contains msg if {
	not allowed_auth_types[input.manifest.auth.type]
	msg := sprintf(
		"AC-6 / MCP-001 violation: unsupported or passthrough auth.type '%v'",
		[input.manifest.auth.type],
	)
}

deny contains msg if {
	input.manifest.auth.passthrough == true
	msg := "AC-6 / MCP-001 violation: client token passthrough is strictly prohibited"
}

# NIST SC-5 / Pattern MCP-003: Bounded Upstream Payload & Timeout
deny contains msg if {
	input.manifest.upstream.max_response_bytes > max_response_bytes_cap
	msg := sprintf(
		"SC-5 / MCP-003 violation: max_response_bytes %d exceeds %d-byte cap",
		[input.manifest.upstream.max_response_bytes, max_response_bytes_cap],
	)
}

deny contains msg if {
	input.manifest.upstream.timeout_seconds > max_timeout_seconds
	msg := sprintf(
		"SC-5 violation: timeout_seconds %v exceeds %vs limit",
		[input.manifest.upstream.timeout_seconds, max_timeout_seconds],
	)
}

# NIST AC-6(10) / Pattern MCP-005: Destructive Tools Require Explicit AppSec Signoff
has_destructive_tool if {
	some tool in input.manifest.tools
	tool.annotations.destructiveHint == true
}

deny contains msg if {
	has_destructive_tool
	input.release.governance.requires_appsec_destructive_signoff != true
	msg := "AC-6(10) violation: destructive tool present but governance.requires_appsec_destructive_signoff != true"
}

deny contains msg if {
	has_destructive_tool
	input.release.governance.appsec_approval.approved != true
	msg := "AC-6(10) violation: destructive tool release requires approved AppSec signoff ticket"
}
