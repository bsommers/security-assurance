"""Deterministic UUIDv5 namespaces and NIST SP 800-53r5 + COSIS + MCP pattern mappings."""

from __future__ import annotations

import uuid
from dataclasses import dataclass

ASSURANCE_NS = uuid.UUID("3f90b2e4-17c8-4a3d-8f50-2a19d47c8053")
OSCAL_VERSION = "1.1.2"
FIXED_TIMESTAMP = "2026-11-19T00:00:00Z"


def det_uuid(seed: str) -> str:
    """Return a deterministic UUIDv5 string for reproducible OSCAL generation."""
    return str(uuid.uuid5(ASSURANCE_NS, seed))


@dataclass(frozen=True)
class ControlSpec:
    oscal_id: str
    nist_id: str
    title: str
    component_key: str  # "chassis" | "overlay" | "organization"
    pattern_refs: tuple[str, ...]
    cosis_use_cases: tuple[str, ...]
    implementation_narrative: str
    human_only: bool = False


FORGE_SSP_CONTROLS: tuple[ControlSpec, ...] = (
    ControlSpec(
        oscal_id="ac-4",
        nist_id="AC-4",
        title="Information Flow Enforcement",
        component_key="chassis",
        pattern_refs=("MCP-003", "MCP-006"),
        cosis_use_cases=("UC-GEN", "UC-AGENT-MULTI"),
        implementation_narrative=(
            "Stateless SEP-2567 execution in src/server.py and src/deps.py eliminates shared "
            "session globals; structured outputs conform to JSON Schema 2020-12 outputSchema."
        ),
    ),
    ControlSpec(
        oscal_id="ac-6",
        nist_id="AC-6",
        title="Least Privilege",
        component_key="chassis",
        pattern_refs=("MCP-001",),
        cosis_use_cases=("UC-AGENT-SINGLE",),
        implementation_narrative=(
            "src/auth.py RouteDispatchAuth resolves server-bound environment credentials per "
            "(HTTP method, path) and prohibits MCP client Authorization header passthrough."
        ),
    ),
    ControlSpec(
        oscal_id="ac-6.1",
        nist_id="AC-6(1)",
        title="Authorize Access to Security Functions",
        component_key="chassis",
        pattern_refs=("MCP-002",),
        cosis_use_cases=("UC-AGENT-MULTI", "UC-DEV"),
        implementation_narrative=(
            "Golden Template security infrastructure (src/auth.py, src/server.py, contract "
            "tests, validate_mcp.py) is locked read-only and guarded by SHA-256 digests."
        ),
    ),
    ControlSpec(
        oscal_id="ac-6.10",
        nist_id="AC-6(10)",
        title="Prohibit Non-Privileged Users from Executing Privileged Functions",
        component_key="overlay",
        pattern_refs=("MCP-005",),
        cosis_use_cases=("UC-AGENT-SINGLE",),
        implementation_narrative=(
            "Destructive operations (delete_incident) declare "
            "ToolAnnotations(destructiveHint=True), "
            "trigger Stage 5 AppSec signoff, and require break-glass tickets in runtime Rego PDP."
        ),
    ),
    ControlSpec(
        oscal_id="au-3",
        nist_id="AU-3",
        title="Content of Audit Records",
        component_key="chassis",
        pattern_refs=("MCP-001", "MCP-008"),
        cosis_use_cases=("UC-GEN",),
        implementation_narrative=(
            "Structured JSON logs emit exclusively to stderr with timestamp, logger, and redacted "
            "upstream error context while keeping stdout pure for JSON-RPC frames."
        ),
    ),
    ControlSpec(
        oscal_id="au-6",
        nist_id="AU-6",
        title="Audit Record Review, Analysis, and Reporting",
        component_key="chassis",
        pattern_refs=("MCP-007", "MCP-008"),
        cosis_use_cases=("UC-AGENT-MULTI",),
        implementation_narrative=(
            "Primitive RFC 9110 x-mcp-header correlation/idempotency metadata and "
            "dashboard/telemetry.py track per-stage validation outcomes across self-healing "
            "iterations."
        ),
    ),
    ControlSpec(
        oscal_id="ca-2",
        nist_id="CA-2",
        title="Control Assessments",
        component_key="chassis",
        pattern_refs=("MCP-002", "MCP-008"),
        cosis_use_cases=("UC-DEV",),
        implementation_narrative=(
            "scripts/validate_mcp.py executes 5 deterministic offline verification gates "
            "independent of generative LLM self-grading."
        ),
    ),
    ControlSpec(
        oscal_id="cm-2",
        nist_id="CM-2",
        title="Baseline Configuration",
        component_key="chassis",
        pattern_refs=("MCP-002",),
        cosis_use_cases=("UC-DEV",),
        implementation_narrative=(
            "golden-template/ maintains the immutable FastMCP 4.x baseline synchronized with "
            "active src/{auth,deps,server}.py modules."
        ),
    ),
    ControlSpec(
        oscal_id="cm-5",
        nist_id="CM-5",
        title="Access Restrictions for Change",
        component_key="chassis",
        pattern_refs=("MCP-002",),
        cosis_use_cases=("UC-DEV",),
        implementation_narrative=(
            "Stage 3 restricts agent writes strictly to src/tools/*.py, tests/unit/*.py, and "
            "README.md via container :ro mounts and LockedWorkspaceDigest SHA-256 checks."
        ),
    ),
    ControlSpec(
        oscal_id="cm-7",
        nist_id="CM-7",
        title="Least Functionality",
        component_key="overlay",
        pattern_refs=("MCP-005", "MCP-008"),
        cosis_use_cases=("UC-AGENT-SINGLE",),
        implementation_narrative=(
            "Enforces <= 15 tools per active profile (acme-incidents exposes 5 tools), bans "
            "deprecated SEP-2577 callbacks, and blocks os/subprocess/socket imports in src/tools/."
        ),
    ),
    ControlSpec(
        oscal_id="ia-9",
        nist_id="IA-9",
        title="Service Identification and Authentication",
        component_key="chassis",
        pattern_refs=("MCP-001", "MCP-005"),
        cosis_use_cases=("UC-AGENT-MULTI",),
        implementation_narrative=(
            "Supports named securitySchemes per OpenAPI operation and prunes unused schemes per "
            "server shard during --auto-split-tags."
        ),
    ),
    ControlSpec(
        oscal_id="pt-2",
        nist_id="PT-2",
        title="Authority to Process Personally Identifiable Information",
        component_key="overlay",
        pattern_refs=("MCP-004", "MCP-007"),
        cosis_use_cases=("UC-GEN", "UC-PRED"),
        implementation_narrative=(
            "Projects upstream responses into explicit typed Pydantic summary models "
            "(<= 8 high-signal fields) and blocks sensitive PII/secret names on x-mcp-header."
        ),
    ),
    ControlSpec(
        oscal_id="sa-8",
        nist_id="SA-8",
        title="Security and Privacy Engineering Principles",
        component_key="chassis",
        pattern_refs=("MCP-001", "MCP-002", "MCP-003", "MCP-004"),
        cosis_use_cases=("UC-DEV",),
        implementation_narrative=(
            "Implements codified secure design patterns MCP-001..MCP-008 from "
            "bsommers/secure-design-patterns across ingestion, template, and runtime layers."
        ),
    ),
    ControlSpec(
        oscal_id="sa-11",
        nist_id="SA-11",
        title="Developer Testing and Evaluation",
        component_key="overlay",
        pattern_refs=("MCP-008",),
        cosis_use_cases=("UC-DEV",),
        implementation_narrative=(
            "Verified via Ruff S+T20, mypy --strict, AST audit, 100.0% branch coverage on "
            "src/tools/, and live subprocess PythonStdioTransport server/discover."
        ),
    ),
    ControlSpec(
        oscal_id="sc-5",
        nist_id="SC-5",
        title="Denial-of-Service Protection",
        component_key="chassis",
        pattern_refs=("MCP-003", "MCP-005", "MCP-006"),
        cosis_use_cases=("UC-GEN", "UC-AGENT-SINGLE", "UC-AGENT-MULTI"),
        implementation_narrative=(
            "Enforces 15.0s upstream HTTP timeout and 32,768-byte ForgeResponseLimitingMiddleware "
            "(string byte axis shipped in v1.3.0; array-cardinality slicing tracked in "
            "POAM-FORGE-W4.4)."
        ),
    ),
    ControlSpec(
        oscal_id="sc-7",
        nist_id="SC-7",
        title="Boundary Protection",
        component_key="chassis",
        pattern_refs=("MCP-004", "MCP-006"),
        cosis_use_cases=("UC-AGENT-SINGLE",),
        implementation_narrative=(
            "Stage 1 normalizer rejects external URI $refs (SSRF block), and runtime tools route "
            "exclusively through the lifespan-pooled ApiClient bound to ACME_BASE_URL."
        ),
    ),
    ControlSpec(
        oscal_id="sc-39",
        nist_id="SC-39",
        title="Process Isolation",
        component_key="chassis",
        pattern_refs=("MCP-002", "MCP-008"),
        cosis_use_cases=("UC-AGENT-SINGLE",),
        implementation_narrative=(
            "Docker synthesis drops all Linux capabilities (--cap-drop=ALL, non-root UID 65532, "
            ":ro rootfs); host fallback kernel seatbelt/bwrap tracked in POAM-FORGE-W5.2."
        ),
    ),
    ControlSpec(
        oscal_id="si-7.1",
        nist_id="SI-7(1)",
        title="Integrity Checks",
        component_key="chassis",
        pattern_refs=("MCP-002",),
        cosis_use_cases=("UC-AGENT-MULTI",),
        implementation_narrative=(
            "LockedWorkspaceDigest verifies pre- and post-turn SHA-256 hashes of every locked "
            "chassis file, restoring bytes and raising TamperDetectionError on drift."
        ),
    ),
    ControlSpec(
        oscal_id="si-10",
        nist_id="SI-10",
        title="Information Input Validation",
        component_key="overlay",
        pattern_refs=("MCP-004", "MCP-007", "MCP-008"),
        cosis_use_cases=("UC-GEN", "UC-PRED"),
        implementation_narrative=(
            "Enforces Pydantic Field constraints, RFC 9110 1*tchar x-mcp-header validation, and "
            "AST docstring prompt-injection checks."
        ),
    ),
    ControlSpec(
        oscal_id="sr-3",
        nist_id="SR-3",
        title="Supply Chain Controls and Processes",
        component_key="chassis",
        pattern_refs=("MCP-002",),
        cosis_use_cases=("UC-DEV",),
        implementation_narrative=(
            "GitHub Actions workflows pin all actions to 40-char commit SHAs with "
            "permissions: contents: read, persist-credentials: false, and locked uv.lock."
        ),
    ),
    # Organizational controls requiring explicit human attestation (never LLM self-attested)
    ControlSpec(
        oscal_id="at-3",
        nist_id="AT-3",
        title="Role-Based Training",
        component_key="organization",
        pattern_refs=(),
        cosis_use_cases=("UC-DEV",),
        implementation_narrative=(
            "[HUMAN ATTESTATION REQUIRED] Organization Security Lead must attest that AI/MCP "
            "engineers completed role-based secure AI/SSDF training."
        ),
        human_only=True,
    ),
    ControlSpec(
        oscal_id="pe-3",
        nist_id="PE-3",
        title="Physical Access Control",
        component_key="organization",
        pattern_refs=(),
        cosis_use_cases=("UC-AGENT-SINGLE",),
        implementation_narrative=(
            "[HUMAN ATTESTATION REQUIRED] Inherited from cloud/datacenter facility authorization; "
            "requires physical security officer signoff."
        ),
        human_only=True,
    ),
    ControlSpec(
        oscal_id="pm-9",
        nist_id="PM-9",
        title="Risk Management Strategy",
        component_key="organization",
        pattern_refs=(),
        cosis_use_cases=("UC-DEV",),
        implementation_narrative=(
            "[HUMAN ATTESTATION REQUIRED] Authorizing Official (AO) risk tolerance and NIST AI RMF "
            "governance charter signoff required."
        ),
        human_only=True,
    ),
    ControlSpec(
        oscal_id="ps-6",
        nist_id="PS-6",
        title="Access Agreements",
        component_key="organization",
        pattern_refs=(),
        cosis_use_cases=("UC-AGENT-SINGLE",),
        implementation_narrative=(
            "[HUMAN ATTESTATION REQUIRED] Privileged incident-commander personnel access "
            "agreements must be attested by HR / Security Operations."
        ),
        human_only=True,
    ),
)
