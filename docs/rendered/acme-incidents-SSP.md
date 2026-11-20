# System Security Plan (SSP) — Acme Incident Management MCP (`acme-incidents`)

> **Auto-generated deterministically from [`../../oscal/ssp-acme-incidents.json`](../../oscal/ssp-acme-incidents.json) (`OSCAL 1.1.2`). Do not hand-edit.**

## 1. System Identification & Authorization Boundary

- **System ID:** `forge-acme-incidents` (`1.4.0`)
- **MCP Protocol Revision:** `2026-07-28`
- **NIST SP 800-53B Baseline:** `moderate`
- **Applied NIST COSIS Overlays:** `UC-AGENT-SINGLE, UC-AGENT-MULTI, UC-DEV`
- **Container Image:** `ghcr.io/bsommers/forged-mcp-acme-incidents:1.4.0`
- **Active Tools (`CM-7`):** `5 / 15 max`
- **AppSec Destructive Tool Approval (`AC-6(10)`):** `SEC-2026-0412` (`appsec-lead@acme.example`)

## 2. Control Implementation & SP 800-53A Assessment Summary

| Control | Title | Component | Patterns | Assessment Status |
|---------|-------|-----------|----------|:-----------------:|
| **AC-4** | Information Flow Enforcement | `chassis` | `MCP-003`, `MCP-006` | `satisfied` |
| **AC-6** | Least Privilege | `chassis` | `MCP-001` | `satisfied` |
| **AC-6(1)** | Authorize Access to Security Functions | `chassis` | `MCP-002` | `satisfied` |
| **AC-6(10)** | Prohibit Non-Privileged Users from Executing Privileged Functions | `overlay` | `MCP-005` | `satisfied` |
| **AU-3** | Content of Audit Records | `chassis` | `MCP-001`, `MCP-008` | `satisfied` |
| **AU-6** | Audit Record Review, Analysis, and Reporting | `chassis` | `MCP-007`, `MCP-008` | `satisfied` |
| **CA-2** | Control Assessments | `chassis` | `MCP-002`, `MCP-008` | `satisfied` |
| **CM-2** | Baseline Configuration | `chassis` | `MCP-002` | `satisfied` |
| **CM-5** | Access Restrictions for Change | `chassis` | `MCP-002` | `satisfied` |
| **CM-7** | Least Functionality | `overlay` | `MCP-005`, `MCP-008` | `satisfied` |
| **IA-9** | Service Identification and Authentication | `chassis` | `MCP-001`, `MCP-005` | `satisfied` |
| **PT-2** | Authority to Process Personally Identifiable Information | `overlay` | `MCP-004`, `MCP-007` | `satisfied` |
| **SA-8** | Security and Privacy Engineering Principles | `chassis` | `MCP-001`, `MCP-002`, `MCP-003`, `MCP-004` | `satisfied` |
| **SA-11** | Developer Testing and Evaluation | `overlay` | `MCP-008` | `satisfied` |
| **SC-5** | Denial-of-Service Protection | `chassis` | `MCP-003`, `MCP-005`, `MCP-006` | `satisfied` |
| **SC-7** | Boundary Protection | `chassis` | `MCP-004`, `MCP-006` | `satisfied` |
| **SC-39** | Process Isolation | `chassis` | `MCP-002`, `MCP-008` | `partially-satisfied` |
| **SI-7(1)** | Integrity Checks | `chassis` | `MCP-002` | `satisfied` |
| **SI-10** | Information Input Validation | `overlay` | `MCP-004`, `MCP-007`, `MCP-008` | `satisfied` |
| **SR-3** | Supply Chain Controls and Processes | `chassis` | `MCP-002` | `satisfied` |
| **AT-3** | Role-Based Training | `organization` | *Org / Human* | `other-than-satisfied` |
| **PE-3** | Physical Access Control | `organization` | *Org / Human* | `other-than-satisfied` |
| **PM-9** | Risk Management Strategy | `organization` | *Org / Human* | `other-than-satisfied` |
| **PS-6** | Access Agreements | `organization` | *Org / Human* | `other-than-satisfied` |

## 3. Active Plan of Action & Milestones (POA&M)

| Gap ID & Control | Scheduled Remediation |
|------------------|-----------------------|
| **POAM-FORGE-W5.2 (SC-39): Host --execution-mode agent relies on chmod 0444 + SHA-256 restore when Docker is absent rather than OS seatbelt/bwrap** | Remediation scheduled in M5 (v2.0.0) — Kernel Host Sandboxing (MCP-008) (target 2027-01-15). |
