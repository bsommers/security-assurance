# AGENTS.md — Continuous Security Assurance (`OSCAL 1.1.2` + `OPA/Rego`)

## 1. Role in the Four-Repository Security Ecosystem
`security-assurance` ties three sibling repositories into an executable Authorization-to-Operate (ATO) & Policy-as-Code pipeline:
1. **[`bsommers/security-controls`](https://github.com/bsommers/security-controls)** — *Normative Requirements*: NIST SP 800-53 Rev. 5 (Update 1) controls + 5 NIST COSIS AI/SI use-case overlays (`OSCAL Profile`).
2. **[`bsommers/secure-design-patterns`](https://github.com/bsommers/secure-design-patterns)** — *Architectural Solutions*: `MCP-001`–`MCP-008` patterns compiled here into a reusable `OSCAL Component Definition`.
3. **[`bsommers/forge`](https://github.com/bsommers/forge)** — *Target System & Evidence*: `acme-incidents` FastMCP 4.x (`2026-07-28`) manifest, release governance bundle, and 5-gate verification telemetry compiled here into an `OSCAL System Security Plan (SSP)`, `Assessment Results (SAR)`, `Plan of Action & Milestones (POA&M)`, and rendered `SSP.md`.

## 2. Core Division of Responsibility: OSCAL vs. Rego
- **NIST OSCAL `1.1.2` JSON = Declarative State & Evidence ("Nouns"):** Portable, schema-validated records of *what controls apply*, *which components implement them*, *what evidence was collected*, and *which gaps are tracked in POA&M*.
- **Open Policy Agent (Rego v1) = Executable Policy Decision Points ("Verbs"):** Deterministic rules evaluating JSON inputs at:
  1. **Build/CI Manifest Gate (`policies/forge/manifest_guard.rego`)**
  2. **ATO / SSP Completeness & POA&M Gate (`policies/oscal/ssp_gate.rego`)**
  3. **Runtime MCP Tool Authorization Gate (`policies/runtime/mcp_tool_authz.rego`)**

## 3. Canonical Commands
- **Rebuild all OSCAL 1.1.2 artifacts & rendered Markdown SSP deterministically:**
  ```bash
  PYTHONPATH=src python3 -m security_assurance.cli build-all
  ```
- **Verify zero drift, Rego v1 hygiene, policy evaluation & Markdown links:**
  ```bash
  python3 scripts/validate_assurance.py
  ```
- **Run OPA Rego unit tests (when `opa` CLI is installed / in CI):**
  ```bash
  opa check --strict policies/ && opa test -v policies/
  ```
- **Run Python test suite, Ruff & strict Mypy:**
  ```bash
  pytest -v && ruff check src scripts tests && mypy --strict -p security_assurance -p scripts
  ```

## 4. Non-Negotiable Grounding Invariants
1. **Zero LLM Self-Attestation:** Non-technical organizational controls (`AT-3`, `PE-3`, `PM-9`, `PS-6`) MUST carry `implementation-status = "planned"` / `human_attestation_required` until signed off by a named human owner—Rego `ssp_gate.rego` denies any SSP where an automated tool claims satisfaction of a human-only control.
2. **Honest Partial Findings + Linked POA&M:** Known technical gaps (e.g., `SC-5` high-cardinality short-string array bounding tracked in Forge `M4 W4.4`) MUST be recorded as `partially-satisfied` in `assessment-results` and backed by an explicit `poam-item`—never hidden.
