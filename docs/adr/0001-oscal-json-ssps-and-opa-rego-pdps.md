# ADR-0001: Canonical OSCAL 1.1.2 JSON SSPs Paired with OPA/Rego Policy Decision Points

- **Status:** Accepted · **Date:** 2026-11-19

[← Back to Documentation Hub](../README.md)

## Context
We need a continuous Authorization-to-Operate (ATO) pipeline connecting normative controls ([`bsommers/security-controls`](https://github.com/bsommers/security-controls)), architectural patterns ([`bsommers/secure-design-patterns`](https://github.com/bsommers/secure-design-patterns)), and AI-forged MCP servers ([`bsommers/forge`](https://github.com/bsommers/forge)) without rotting Word/Confluence SSP documents or ungrounded LLM self-certification.

## Decision
1. Represent **declarative compliance state & evidence ("nouns")** in **NIST OSCAL `1.1.2` JSON** (`component-definition`, `system-security-plan`, `assessment-results`, and `plan-of-action-and-milestones`), and deterministically render human-readable Markdown (`docs/rendered/*-SSP.md`) from those JSON files.
2. Represent **executable gate & authorization logic ("verbs")** in **Open Policy Agent (Rego v1)** across three Policy Decision Points: Build/Manifest (`manifest_guard.rego`), ATO/SSP (`ssp_gate.rego`), and Runtime Tool AuthZ (`mcp_tool_authz.rego`).

## Consequences
- **Pros:** Machine-verifiable in CI (`< 50 ms`), inherits ~80% of technical controls from the Golden Template `component-definition`, blocks silent prose drift, and enforces explicit POA&M tracking for partial controls (`SC-5`, `SC-39`).
- **Cons:** Raw OSCAL JSON is verbose (~300–600 lines per SSP) and requires a compiler + Markdown renderer so human reviewers do not edit raw UUID graphs by hand.

## Defense

### Stability
- **Failure modes:** Non-deterministic UUID churn polluting git diffs; an LLM marking human-only controls (`AT-3`, `PE-3`, `PM-9`, `PS-6`) `satisfied`; or partial technical controls slipping into production without remediation tracking.
- **Invariants:** Deterministic UUIDv5 (`ASSURANCE_NS`) + fixed epoch metadata ensure byte-identical rebuilds; `ssp_gate.rego` denies non-human attestation of organizational controls and denies untracked `partially-satisfied` findings.

### Critic
- **Strongest objection:** *"Why use both OSCAL and Rego? Why not Markdown-only SSPs or pure Python assertions?"*
- **Alternatives rejected:**
  1. *Prose-only Markdown/Docx SSPs:* Rejected — impossible to query structurally across hundreds of controls or join against POA&M items in CI.
  2. *OSCAL without Rego:* Rejected — OSCAL is a data schema, not a rule engine; it cannot express conditional release policies (e.g., *"allow `partially-satisfied` iff a linked POA&M item exists, and require break-glass tickets on `destructiveHint: true` tools"*).
  3. *Ad-hoc Python `if` scripts without Rego:* Rejected — Rego provides a declarative, side-effect-free, portable PDP standard reusable across CI (`conftest`/`opa eval`), Kubernetes admission, and Envoy/FastMCP runtime middleware.

## Enforced By
- `scripts/validate_assurance.py` (byte-identical drift gate)
- `opa check --strict policies/ && opa test -v policies/` in `.github/workflows/ci.yml`
- `tests/test_security_assurance.py`
