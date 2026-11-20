package assurance.oscal.ssp_gate

import rego.v1

# Mandatory P1 technical controls for NIST COSIS UC-AGENT-SINGLE + UC-DEV
required_p1_controls := {
	"ac-6",
	"ac-6.1",
	"ac-6.10",
	"cm-2",
	"cm-5",
	"cm-7",
	"sa-8",
	"sa-11",
	"sc-5",
	"sc-7",
	"sc-39",
	"si-7.1",
	"si-10",
	"sr-3",
}

# Non-technical organizational controls that MUST NOT be machine/LLM self-attested
human_only_controls := {"at-3", "pe-3", "pm-9", "ps-6"}

default allow := false

allow if {
	count(deny) == 0
}

implemented_control_ids contains cid if {
	some req in input.ssp["system-security-plan"]["control-implementation"]["implemented-requirements"]
	cid := req["control-id"]
}

poam_tracked_controls contains cid if {
	some item in input.poam["plan-of-action-and-milestones"]["poam-items"]
	some prop in item.props
	prop.name == "control-id"
	cid := prop.value
}

# Rule 1: Every required P1 COSIS control MUST exist in the OSCAL SSP
deny contains msg if {
	some req_cid in required_p1_controls
	not implemented_control_ids[req_cid]
	msg := sprintf("OSCAL SSP incomplete: missing required COSIS P1 control '%s'", [req_cid])
}

# Rule 2: Grounding Guardrail — Automated/LLM assessors MUST NOT mark human-only controls 'satisfied'
deny contains msg if {
	some finding in input.sar["assessment-results"].results[0].findings
	cid := finding.target["target-id"]
	human_only_controls[cid]
	finding.target.status.state == "satisfied"
	some prop in finding.props
	prop.name == "assessor-type"
	prop.value != "human-official"
	msg := sprintf(
		"Grounding violation (CA-2): organizational control '%s' cannot be machine-attested as satisfied",
		[cid],
	)
}

# Rule 3: Any technical control that is 'not-satisfied' or 'partially-satisfied' MUST link to an active POA&M item
deny contains msg if {
	some finding in input.sar["assessment-results"].results[0].findings
	cid := finding.target["target-id"]
	not human_only_controls[cid]
	state := finding.target.status.state
	state != "satisfied"
	not poam_tracked_controls[cid]
	msg := sprintf(
		"RMF ATO block: control '%s' has state '%s' with no active remediation entry in OSCAL POA&M",
		[cid, state],
	)
}
