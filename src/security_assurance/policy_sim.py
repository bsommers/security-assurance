"""Offline Python mirror of the 3 Rego v1 policy suites for zero-binary local verification."""

from __future__ import annotations

from typing import Any

ALLOWED_AUTH_TYPES = frozenset(
    {"bearer", "api_key_header", "api_key_query", "basic", "oauth2_client_credentials"}
)
REQUIRED_P1_CONTROLS = frozenset(
    {
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
)
HUMAN_ONLY_CONTROLS = frozenset({"at-3", "pe-3", "pm-9", "ps-6"})


def evaluate_forge_manifest_guard(bundle: dict[str, Any]) -> list[str]:
    """Mirror policies/forge/manifest_guard.rego; returns list of deny messages (empty = allow)."""
    denies: list[str] = []
    manifest = bundle["manifest"]
    release = bundle["release"]

    if manifest.get("protocol_revision") != "2026-07-28":
        denies.append(
            f"Protocol violation: expected protocol_revision '2026-07-28', "
            f"got '{manifest.get('protocol_revision')}'"
        )

    tools = manifest.get("tools", [])
    if len(tools) > 15:
        denies.append(
            f"CM-7 / MCP-005 violation: manifest defines {len(tools)} tools (max allowed is 15)"
        )

    auth = manifest.get("auth", {})
    if auth.get("type") not in ALLOWED_AUTH_TYPES:
        denies.append(
            f"AC-6 / MCP-001 violation: unsupported or passthrough auth.type '{auth.get('type')}'"
        )
    if auth.get("passthrough") is True:
        denies.append("AC-6 / MCP-001 violation: client token passthrough is strictly prohibited")

    upstream = manifest.get("upstream", {})
    if int(upstream.get("max_response_bytes", 0)) > 32768:
        denies.append(
            f"SC-5 / MCP-003 violation: max_response_bytes "
            f"{upstream.get('max_response_bytes')} exceeds 32768-byte cap"
        )
    if float(upstream.get("timeout_seconds", 0.0)) > 30.0:
        denies.append(
            f"SC-5 violation: timeout_seconds {upstream.get('timeout_seconds')} exceeds 30s limit"
        )

    has_destructive = any(
        bool(t.get("annotations", {}).get("destructiveHint")) for t in tools
    )
    if has_destructive:
        gov = release.get("governance", {})
        if gov.get("requires_appsec_destructive_signoff") is not True:
            denies.append(
                "AC-6(10) violation: destructive tool present but "
                "governance.requires_appsec_destructive_signoff != true"
            )
        if gov.get("appsec_approval", {}).get("approved") is not True:
            denies.append(
                "AC-6(10) violation: destructive tool release requires approved AppSec signoff"
            )

    return denies


def evaluate_oscal_ssp_gate(oscal_input: dict[str, Any]) -> list[str]:
    """Mirror policies/oscal/ssp_gate.rego; returns list of deny messages (empty = allow)."""
    denies: list[str] = []
    reqs = oscal_input["ssp"]["system-security-plan"]["control-implementation"][
        "implemented-requirements"
    ]
    implemented_ids = {r["control-id"] for r in reqs}

    for req_cid in sorted(REQUIRED_P1_CONTROLS):
        if req_cid not in implemented_ids:
            denies.append(
                f"OSCAL SSP incomplete: missing required COSIS P1 control '{req_cid}'"
            )

    poam_items = oscal_input["poam"]["plan-of-action-and-milestones"]["poam-items"]
    poam_controls: set[str] = set()
    for item in poam_items:
        for prop in item.get("props", []):
            if prop.get("name") == "control-id":
                poam_controls.add(str(prop["value"]))

    findings = oscal_input["sar"]["assessment-results"]["results"][0]["findings"]
    for finding in findings:
        cid = str(finding["target"]["target-id"])
        state = str(finding["target"]["status"]["state"])
        props = {p["name"]: p["value"] for p in finding.get("props", [])}

        if (
            cid in HUMAN_ONLY_CONTROLS
            and state == "satisfied"
            and props.get("assessor-type") != "human-official"
        ):
            denies.append(
                f"Grounding violation (CA-2): organizational control '{cid}' "
                "cannot be machine-attested as satisfied"
            )

        if cid not in HUMAN_ONLY_CONTROLS and state != "satisfied" and cid not in poam_controls:
            denies.append(
                f"RMF ATO block: control '{cid}' has state '{state}' "
                "with no active remediation entry in OSCAL POA&M"
            )

    return denies


def evaluate_runtime_tool_authz(caller: dict[str, Any], tool: dict[str, Any]) -> bool:
    """Mirror policies/runtime/mcp_tool_authz.rego allow decision."""
    ann = tool.get("annotations", {})
    read_only = bool(ann.get("readOnlyHint"))
    destructive = bool(ann.get("destructiveHint"))
    role = str(caller.get("role", ""))
    ticket = str(caller.get("elevation_ticket", ""))

    if read_only and not destructive:
        return role in {
            "incident-triage-readonly",
            "incident-responder",
            "incident-commander",
        }
    if not read_only and not destructive:
        return role in {"incident-responder", "incident-commander"}
    if destructive:
        return role == "incident-commander" and ticket.startswith("INC-BREAKGLASS-")
    return False
