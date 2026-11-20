"""Compiler generating NIST OSCAL 1.1.2 Component Def, SSP, SAR, POA&M, and Markdown SSP."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from security_assurance.constants import (
    FIXED_TIMESTAMP,
    FORGE_SSP_CONTROLS,
    OSCAL_VERSION,
    det_uuid,
)

CONTROLS_PROFILE_HREF = (
    "https://github.com/bsommers/security-controls/blob/main/"
    "catalog/cosis/use-cases.json"
)
PATTERNS_CATALOG_HREF = (
    "https://github.com/bsommers/secure-design-patterns/blob/main/"
    "patterns/mcp-serve/catalog.json"
)


@dataclass(frozen=True)
class AssuranceBundle:
    """All deterministically compiled OSCAL 1.1.2 JSON models and rendered Markdown SSP."""

    component_definition: dict[str, Any]
    ssp: dict[str, Any]
    assessment_results: dict[str, Any]
    poam: dict[str, Any]
    markdown_ssp: str


def _load_json(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"Expected JSON object in {path}")
    return data


def compile_forge_assurance_bundle(fixtures_dir: Path) -> AssuranceBundle:
    """Compile Forge manifest + release + 5-gate evidence into OSCAL 1.1.2 SSP, SAR, and POA&M."""
    manifest = _load_json(fixtures_dir / "forge-manifest.json")
    release = _load_json(fixtures_dir / "forge-release-artifacts.json")
    evidence = _load_json(fixtures_dir / "validate-mcp-evidence.json")

    chassis_uuid = det_uuid("component:forge-golden-template-chassis")
    overlay_uuid = det_uuid(f"component:forged-overlay:{manifest['server_name']}")
    org_uuid = det_uuid("component:acme-organization-governance")
    comp_map = {
        "chassis": chassis_uuid,
        "overlay": overlay_uuid,
        "organization": org_uuid,
    }

    # 1. OSCAL Component Definition (Golden Template + Secure Design Patterns MCP-001..008)
    chassis_reqs = [
        {
            "uuid": det_uuid(f"comp-req:chassis:{c.oscal_id}"),
            "control-id": c.oscal_id,
            "description": c.implementation_narrative,
            "props": [
                {"name": "secure-design-patterns", "value": ",".join(c.pattern_refs)},
                {"name": "cosis-use-cases", "value": ",".join(c.cosis_use_cases)},
            ],
        }
        for c in FORGE_SSP_CONTROLS
        if c.component_key == "chassis"
    ]

    component_definition: dict[str, Any] = {
        "component-definition": {
            "uuid": det_uuid("compdef:mcp-forge-golden-template"),
            "metadata": {
                "title": "MCP Server Forge Golden Template Component Definition (MCP-001..008)",
                "last-modified": FIXED_TIMESTAMP,
                "version": str(manifest["version"]),
                "oscal-version": OSCAL_VERSION,
                "props": [
                    {"name": "patterns-source", "value": PATTERNS_CATALOG_HREF},
                    {"name": "controls-source", "value": CONTROLS_PROFILE_HREF},
                ],
            },
            "components": [
                {
                    "uuid": chassis_uuid,
                    "type": "software",
                    "title": "FastMCP 4.x Locked Golden Template Chassis",
                    "description": (
                        "Immutable auth, lifespan connection pool, dual-axis payload middleware, "
                        "and 5-gate verification harness implementing MCP-001..MCP-008."
                    ),
                    "control-implementations": [
                        {
                            "uuid": det_uuid("comp-impl:chassis:sp800-53r5-cosis"),
                            "source": CONTROLS_PROFILE_HREF,
                            "description": "NIST SP 800-53r5 Update 1 + COSIS technical controls.",
                            "implemented-requirements": chassis_reqs,
                        }
                    ],
                }
            ],
        }
    }

    # 2. OSCAL System Security Plan (SSP) for acme-incidents
    ssp_uuid = det_uuid(f"ssp:{evidence['system_id']}")
    ssp_impl_reqs: list[dict[str, Any]] = []
    for c in FORGE_SSP_CONTROLS:
        status_state = "planned" if c.human_only else "implemented"
        ssp_impl_reqs.append(
            {
                "uuid": det_uuid(f"ssp-req:{manifest['server_name']}:{c.oscal_id}"),
                "control-id": c.oscal_id,
                "props": [
                    {"name": "nist-id", "value": c.nist_id},
                    {"name": "implementation-status", "value": status_state},
                    {
                        "name": "secure-design-patterns",
                        "value": ",".join(c.pattern_refs) if c.pattern_refs else "organizational",
                    },
                ],
                "by-components": [
                    {
                        "component-uuid": comp_map[c.component_key],
                        "uuid": det_uuid(f"by-comp:{c.component_key}:{c.oscal_id}"),
                        "description": c.implementation_narrative,
                    }
                ],
            }
        )

    ssp: dict[str, Any] = {
        "system-security-plan": {
            "uuid": ssp_uuid,
            "metadata": {
                "title": (
                    f"System Security Plan (SSP) — {manifest['title']} ({manifest['server_name']})"
                ),
                "last-modified": FIXED_TIMESTAMP,
                "version": str(manifest["version"]),
                "oscal-version": OSCAL_VERSION,
                "props": [
                    {"name": "protocol-revision", "value": str(manifest["protocol_revision"])},
                    {"name": "cosis-use-cases", "value": ",".join(evidence["cosis_use_cases"])},
                    {"name": "sp800-53b-baseline", "value": str(evidence["baseline"])},
                ],
            },
            "import-profile": {"href": CONTROLS_PROFILE_HREF},
            "system-characteristics": {
                "system-ids": [{"id": str(evidence["system_id"])}],
                "system-name": str(manifest["title"]),
                "description": str(manifest["description"]),
                "security-sensitivity-level": str(evidence["baseline"]),
                "status": {"state": "operational"},
                "props": [
                    {"name": "container-image", "value": str(release["container_image"])},
                    {"name": "active-tool-count", "value": str(len(manifest["tools"]))},
                    {
                        "name": "max-response-bytes",
                        "value": str(manifest["upstream"]["max_response_bytes"]),
                    },
                    {
                        "name": "appsec-signoff-ticket",
                        "value": str(release["governance"]["appsec_approval"]["ticket"]),
                    },
                ],
            },
            "system-implementation": {
                "components": [
                    {
                        "uuid": chassis_uuid,
                        "type": "software",
                        "title": "FastMCP 4.x Golden Template Chassis (Locked :ro)",
                        "description": "Provides server-bound auth, lifespan pool, and middleware.",
                        "status": {"state": "operational"},
                    },
                    {
                        "uuid": overlay_uuid,
                        "type": "software",
                        "title": f"Forged Domain Tool Overlay ({manifest['server_name']})",
                        "description": (
                            "5 stateless incident tools verified at 100% branch coverage."
                        ),
                        "status": {"state": "operational"},
                    },
                    {
                        "uuid": org_uuid,
                        "type": "policy",
                        "title": "Organizational Governance & Facility Controls",
                        "description": (
                            "Human-attested training, physical, and RMF governance controls."
                        ),
                        "status": {"state": "under-development"},
                    },
                ]
            },
            "control-implementation": {
                "description": (
                    "Component-inherited NIST SP 800-53r5 Update 1 + COSIS control implementation "
                    "backed by bsommers/secure-design-patterns (MCP-001..008)."
                ),
                "implemented-requirements": ssp_impl_reqs,
            },
        }
    }

    # 3. OSCAL Assessment Results (SAR) + 4. OSCAL POA&M
    gaps_by_ctrl = {g["control_id"]: g for g in evidence.get("known_limitations", [])}
    findings: list[dict[str, Any]] = []
    poam_items: list[dict[str, Any]] = []

    for c in FORGE_SSP_CONTROLS:
        if c.human_only:
            state = "other-than-satisfied"
            assessor_type = "human-attestation-pending"
            obs = (
                "Awaiting named organizational official signoff; automated LLM grading prohibited."
            )
        elif c.oscal_id in gaps_by_ctrl:
            gap = gaps_by_ctrl[c.oscal_id]
            state = "partially-satisfied"
            assessor_type = "automated-gate"
            obs = f"Tracked in {gap['gap_id']}: {gap['title']} -> {gap['remediation_milestone']}"
            poam_items.append(
                {
                    "uuid": det_uuid(f"poam-item:{gap['gap_id']}"),
                    "title": f"{gap['gap_id']} ({c.nist_id}): {gap['title']}",
                    "description": (
                        f"Remediation scheduled in {gap['remediation_milestone']} "
                        f"(target {gap['target_date']})."
                    ),
                    "props": [
                        {"name": "gap-id", "value": str(gap["gap_id"])},
                        {"name": "control-id", "value": c.oscal_id},
                        {"name": "target-date", "value": str(gap["target_date"])},
                    ],
                }
            )
        else:
            state = "satisfied"
            assessor_type = "automated-gate"
            obs = (
                "Verified deterministically by validate_mcp.py 5-gate harness "
                f"(branch coverage={evidence['gates']['gate_4_pytest_branch_coverage_pct']}%)."
            )

        findings.append(
            {
                "uuid": det_uuid(f"finding:{manifest['server_name']}:{c.oscal_id}"),
                "title": f"{c.nist_id} — {c.title}",
                "description": obs,
                "target": {
                    "type": "objective-id",
                    "target-id": c.oscal_id,
                    "status": {"state": state},
                },
                "props": [
                    {"name": "assessor-type", "value": assessor_type},
                    {
                        "name": "patterns",
                        "value": ",".join(c.pattern_refs) if c.pattern_refs else "none",
                    },
                ],
            }
        )

    assessment_results: dict[str, Any] = {
        "assessment-results": {
            "uuid": det_uuid(f"sar:{evidence['system_id']}"),
            "metadata": {
                "title": f"SP 800-53A Automated Assessment Results — {manifest['title']}",
                "last-modified": FIXED_TIMESTAMP,
                "version": str(manifest["version"]),
                "oscal-version": OSCAL_VERSION,
            },
            "import-ssp": {"href": "ssp-acme-incidents.json"},
            "results": [
                {
                    "uuid": det_uuid(f"sar-result:{evidence['system_id']}"),
                    "title": "Forge 5-Gate + OPA/Rego Continuous Assurance Run",
                    "description": "Deterministic SP 800-53A technical gate evaluation.",
                    "start": FIXED_TIMESTAMP,
                    "findings": findings,
                }
            ],
        }
    }

    poam: dict[str, Any] = {
        "plan-of-action-and-milestones": {
            "uuid": det_uuid(f"poam:{evidence['system_id']}"),
            "metadata": {
                "title": f"Plan of Action and Milestones (POA&M) — {manifest['title']}",
                "last-modified": FIXED_TIMESTAMP,
                "version": str(manifest["version"]),
                "oscal-version": OSCAL_VERSION,
            },
            "import-ssp": {"href": "ssp-acme-incidents.json"},
            "poam-items": poam_items,
        }
    }

    markdown_ssp = render_markdown_ssp(manifest, release, evidence, findings, poam_items)
    return AssuranceBundle(
        component_definition=component_definition,
        ssp=ssp,
        assessment_results=assessment_results,
        poam=poam,
        markdown_ssp=markdown_ssp,
    )


def render_markdown_ssp(
    manifest: dict[str, Any],
    release: dict[str, Any],
    evidence: dict[str, Any],
    findings: list[dict[str, Any]],
    poam_items: list[dict[str, Any]],
) -> str:
    """Deterministically render a human/AO-readable Markdown SSP from OSCAL structures."""
    finding_state = {f["target"]["target-id"]: f["target"]["status"]["state"] for f in findings}
    lines = [
        f"# System Security Plan (SSP) — {manifest['title']} (`{manifest['server_name']}`)",
        "",
        "> **Auto-generated deterministically from [`../../oscal/ssp-acme-incidents.json`]"
        "(../../oscal/ssp-acme-incidents.json) (`OSCAL 1.1.2`). Do not hand-edit.**",
        "",
        "## 1. System Identification & Authorization Boundary",
        "",
        f"- **System ID:** `{evidence['system_id']}` (`{manifest['version']}`)",
        f"- **MCP Protocol Revision:** `{manifest['protocol_revision']}`",
        f"- **NIST SP 800-53B Baseline:** `{evidence['baseline']}`",
        f"- **Applied NIST COSIS Overlays:** `{', '.join(evidence['cosis_use_cases'])}`",
        f"- **Container Image:** `{release['container_image']}`",
        f"- **Active Tools (`CM-7`):** `{len(manifest['tools'])} / 15 max`",
        f"- **AppSec Destructive Tool Approval (`AC-6(10)`):** "
        f"`{release['governance']['appsec_approval']['ticket']}` "
        f"(`{release['governance']['appsec_approval']['approver']}`)",
        "",
        "## 2. Control Implementation & SP 800-53A Assessment Summary",
        "",
        "| Control | Title | Component | Patterns | Assessment Status |",
        "|---------|-------|-----------|----------|:-----------------:|",
    ]
    for c in FORGE_SSP_CONTROLS:
        pats = ", ".join(f"`{p}`" for p in c.pattern_refs) if c.pattern_refs else "*Org / Human*"
        st = finding_state[c.oscal_id]
        lines.append(
            f"| **{c.nist_id}** | {c.title} | `{c.component_key}` | {pats} | `{st}` |"
        )

    lines.extend(
        [
            "",
            "## 3. Active Plan of Action & Milestones (POA&M)",
            "",
            "| Gap ID & Control | Scheduled Remediation |",
            "|------------------|-----------------------|",
        ]
    )
    for item in poam_items:
        lines.append(f"| **{item['title']}** | {item['description']} |")

    lines.append("")
    return "\n".join(lines)
