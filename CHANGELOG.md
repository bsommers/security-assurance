# Changelog

## [1.1.0] - 2026-11-21

### Changed
- **Closed `POAM-FORGE-W5.2` (`NIST SC-39` -> `satisfied`, `0` open POA&M items)**:
  - Updated `forge-acme-incidents` continuous assurance bundle to `bsommers/forge` `v2.0.0` (`forge/sandbox.py` macOS `sandbox-exec` / Linux `bwrap` host isolation + recorded contract fixture replay) and `bsommers/security-controls` `v1.1.0` (`1,189`-control NIST SP 800-53 Rev. 5.1.1 index).

## [1.0.0] - 2026-11-19

### Added
- **Four-Repository Assurance Compiler (`src/security_assurance/compiler.py`)**: Synthesizes NIST OSCAL `1.1.2` `component-definition`, `system-security-plan` (SSP), `assessment-results` (SAR), `plan-of-action-and-milestones` (POA&M), and human-readable `docs/rendered/acme-incidents-SSP.md` from `bsommers/security-controls`, `bsommers/secure-design-patterns`, and `bsommers/forge` (`acme-incidents`).
- **Three Open Policy Agent (Rego v1) Policy Suites & Unit Tests (`policies/`)**:
  - `policies/forge/manifest_guard.rego` (+ `_test.rego`) — Build-time manifest & destructive-tool governance gate.
  - `policies/oscal/ssp_gate.rego` (+ `_test.rego`) — ATO compliance gate enforcing P1 coverage, anti-LLM-self-attestation on organizational controls, and mandatory POA&M linkage for partial findings.
  - `policies/runtime/mcp_tool_authz.rego` (+ `_test.rego`) — Runtime RBAC & elevation-ticket PDP for read-only, mutating, and destructive MCP tool invocations.
- **Architecture Documentation & Defended ADR (`docs/ARCHITECTURE_OSCAL_AND_REGO.md`, `docs/adr/0001-oscal-json-ssps-and-opa-rego-pdps.md`)**.
- **Hardened CI Pipeline (`.github/workflows/ci.yml`)**: Executes real `opa check --strict`, `opa test -v`, and live `opa eval` against the compiled Forge OSCAL SSP alongside `ruff`, `mypy --strict`, and `pytest`.
