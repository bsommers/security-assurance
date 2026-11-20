package assurance.oscal.ssp_gate_test

import rego.v1

import data.assurance.oscal.ssp_gate

all_p1_reqs := [
	{"control-id": cid} |
	some cid in ssp_gate.required_p1_controls
]

valid_oscal_bundle := {
	"ssp": {
		"system-security-plan": {
			"control-implementation": {
				"implemented-requirements": all_p1_reqs,
			},
		},
	},
	"sar": {
		"assessment-results": {
			"results": [{
				"findings": [
					{
						"target": {"target-id": "ac-6", "status": {"state": "satisfied"}},
						"props": [{"name": "assessor-type", "value": "automated-gate"}],
					},
					{
						"target": {"target-id": "sc-5", "status": {"state": "partially-satisfied"}},
						"props": [{"name": "assessor-type", "value": "automated-gate"}],
					},
					{
						"target": {"target-id": "at-3", "status": {"state": "other-than-satisfied"}},
						"props": [{"name": "assessor-type", "value": "human-attestation-pending"}],
					},
				],
			}],
		},
	},
	"poam": {
		"plan-of-action-and-milestones": {
			"poam-items": [{
				"title": "POAM-FORGE-W4.4",
				"props": [{"name": "control-id", "value": "sc-5"}],
			}],
		},
	},
}

test_valid_ssp_with_tracked_poam_allowed if {
	ssp_gate.allow with input as valid_oscal_bundle
}

test_untracked_partial_finding_denied if {
	empty_poam := object.union(valid_oscal_bundle, {
		"poam": {"plan-of-action-and-milestones": {"poam-items": []}},
	})
	not ssp_gate.allow with input as empty_poam
	some msg in ssp_gate.deny with input as empty_poam
	contains(msg, "sc-5")
}

test_machine_self_attesting_human_control_denied if {
	forged_human := object.union(valid_oscal_bundle, {
		"sar": {
			"assessment-results": {
				"results": [{
					"findings": [{
						"target": {"target-id": "at-3", "status": {"state": "satisfied"}},
						"props": [{"name": "assessor-type", "value": "llm-agent"}],
					}],
				}],
			},
		},
	})
	not ssp_gate.allow with input as forged_human
	some msg in ssp_gate.deny with input as forged_human
	contains(msg, "CA-2")
}
