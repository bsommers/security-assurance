package assurance.forge.manifest_guard_test

import rego.v1

import data.assurance.forge.manifest_guard

valid_bundle := {
	"manifest": {
		"protocol_revision": "2026-07-28",
		"upstream": {"timeout_seconds": 15.0, "max_response_bytes": 32768},
		"auth": {"type": "bearer", "token_env": "ACME_API_TOKEN"},
		"tools": [
			{"name": "get_incident", "annotations": {"destructiveHint": false}},
			{"name": "delete_incident", "annotations": {"destructiveHint": true}},
		],
	},
	"release": {
		"governance": {
			"requires_appsec_destructive_signoff": true,
			"appsec_approval": {"approved": true, "ticket": "SEC-2026-0412"},
		},
	},
}

test_valid_forge_bundle_allowed if {
	manifest_guard.allow with input as valid_bundle
}

test_token_passthrough_denied if {
	bad := object.union(valid_bundle, {"manifest": object.union(valid_bundle.manifest, {"auth": {"type": "bearer", "passthrough": true}})})
	not manifest_guard.allow with input as bad
	some msg in manifest_guard.deny with input as bad
	contains(msg, "MCP-001")
}

test_oversized_toolset_denied if {
	many_tools := [
		{"name": sprintf("t_%d", [i]), "annotations": {"destructiveHint": false}} |
		some i in numbers.range(1, 16)
	]
	bad := object.union(valid_bundle, {"manifest": object.union(valid_bundle.manifest, {"tools": many_tools})})
	not manifest_guard.allow with input as bad
	some msg in manifest_guard.deny with input as bad
	contains(msg, "CM-7")
}

test_missing_appsec_signoff_on_destructive_tool_denied if {
	bad := object.union(valid_bundle, {
		"release": {
			"governance": {
				"requires_appsec_destructive_signoff": true,
				"appsec_approval": {"approved": false},
			},
		},
	})
	not manifest_guard.allow with input as bad
	some msg in manifest_guard.deny with input as bad
	contains(msg, "AC-6(10)")
}

test_excessive_payload_cap_denied if {
	bad := object.union(valid_bundle, {
		"manifest": object.union(valid_bundle.manifest, {
			"upstream": {"timeout_seconds": 15.0, "max_response_bytes": 131072},
		}),
	})
	not manifest_guard.allow with input as bad
	some msg in manifest_guard.deny with input as bad
	contains(msg, "SC-5")
}
