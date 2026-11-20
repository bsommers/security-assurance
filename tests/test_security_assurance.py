"""Tests verifying OSCAL 1.1.2 SSP compilation, POA&M enforcement, and Rego policy contracts."""

from __future__ import annotations

import copy
import json

from scripts.validate_assurance import ROOT, validate_repository
from security_assurance.cli import main as cli_main
from security_assurance.compiler import compile_forge_assurance_bundle
from security_assurance.policy_sim import (
    evaluate_forge_manifest_guard,
    evaluate_oscal_ssp_gate,
    evaluate_runtime_tool_authz,
)


def test_repository_zero_drift_rego_hygiene_and_links() -> None:
    assert validate_repository(ROOT) == []


def test_oscal_ssp_compilation_is_byte_deterministic() -> None:
    fixtures_dir = ROOT / "fixtures" / "forge-acme-incidents"
    bundle_a = compile_forge_assurance_bundle(fixtures_dir)
    bundle_b = compile_forge_assurance_bundle(fixtures_dir)

    assert json.dumps(bundle_a.ssp, sort_keys=True) == json.dumps(bundle_b.ssp, sort_keys=True)
    assert bundle_a.markdown_ssp == bundle_b.markdown_ssp
    assert bundle_a.ssp["system-security-plan"]["metadata"]["oscal-version"] == "1.1.2"
    # POAM-FORGE-W4.4 (sc-5) is closed in Forge v1.4.0; only POAM-FORGE-W5.2 (sc-39) remains open
    assert len(bundle_a.poam["plan-of-action-and-milestones"]["poam-items"]) == 1
    sc5 = next(
        f
        for f in bundle_a.assessment_results["assessment-results"]["results"][0]["findings"]
        if f["target"]["target-id"] == "sc-5"
    )
    assert sc5["target"]["status"]["state"] == "satisfied"


def test_manifest_guard_blocks_passthrough_oversized_tools_and_unsigned_destructive() -> None:
    fixtures_dir = ROOT / "fixtures" / "forge-acme-incidents"
    manifest = json.loads((fixtures_dir / "forge-manifest.json").read_text(encoding="utf-8"))
    release = json.loads(
        (fixtures_dir / "forge-release-artifacts.json").read_text(encoding="utf-8")
    )
    valid = {"manifest": manifest, "release": release}
    assert evaluate_forge_manifest_guard(valid) == []

    passthrough = copy.deepcopy(valid)
    passthrough["manifest"]["auth"]["passthrough"] = True
    assert any("MCP-001" in m for m in evaluate_forge_manifest_guard(passthrough))

    unsigned = copy.deepcopy(valid)
    unsigned["release"]["governance"]["appsec_approval"]["approved"] = False
    assert any("AC-6(10)" in m for m in evaluate_forge_manifest_guard(unsigned))

    sixteen_tools = copy.deepcopy(valid)
    sixteen_tools["manifest"]["tools"] = [
        {"name": f"t_{i}", "annotations": {"destructiveHint": False}} for i in range(16)
    ]
    assert any("CM-7" in m for m in evaluate_forge_manifest_guard(sixteen_tools))


def test_oscal_ssp_gate_enforces_poam_and_blocks_llm_self_attestation() -> None:
    bundle = compile_forge_assurance_bundle(ROOT / "fixtures" / "forge-acme-incidents")
    valid_input = {
        "ssp": bundle.ssp,
        "sar": bundle.assessment_results,
        "poam": bundle.poam,
    }
    assert evaluate_oscal_ssp_gate(valid_input) == []

    # Removing POA&M items blocks ATO because sc-39 is partially-satisfied on host
    missing_poam = copy.deepcopy(valid_input)
    missing_poam["poam"]["plan-of-action-and-milestones"]["poam-items"] = []
    denies = evaluate_oscal_ssp_gate(missing_poam)
    assert any("sc-39" in d for d in denies)

    # Machine/LLM claiming organizational control at-3 is satisfied is denied (CA-2)
    forged_human = copy.deepcopy(valid_input)
    for finding in forged_human["sar"]["assessment-results"]["results"][0]["findings"]:
        if finding["target"]["target-id"] == "at-3":
            finding["target"]["status"]["state"] = "satisfied"
            finding["props"] = [{"name": "assessor-type", "value": "llm-agent"}]
    assert any("CA-2" in d for d in evaluate_oscal_ssp_gate(forged_human))


def test_runtime_mcp_tool_authz_tiers() -> None:
    get_tool = {
        "name": "get_incident",
        "annotations": {"readOnlyHint": True, "destructiveHint": False},
    }
    upd_tool = {
        "name": "update_incident_status",
        "annotations": {"readOnlyHint": False, "destructiveHint": False},
    }
    del_tool = {
        "name": "delete_incident",
        "annotations": {"readOnlyHint": False, "destructiveHint": True},
    }

    assert evaluate_runtime_tool_authz({"role": "incident-triage-readonly"}, get_tool) is True
    assert evaluate_runtime_tool_authz({"role": "incident-triage-readonly"}, upd_tool) is False
    assert evaluate_runtime_tool_authz({"role": "incident-responder"}, upd_tool) is True
    assert evaluate_runtime_tool_authz({"role": "incident-responder"}, del_tool) is False
    assert (
        evaluate_runtime_tool_authz(
            {"role": "incident-commander", "elevation_ticket": ""}, del_tool
        )
        is False
    )
    assert (
        evaluate_runtime_tool_authz(
            {"role": "incident-commander", "elevation_ticket": "INC-BREAKGLASS-9042"},
            del_tool,
        )
        is True
    )


def test_cli_evaluate_succeeds() -> None:
    assert cli_main(["evaluate"]) == 0
