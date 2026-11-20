# Strategic Assessment: What the Four-Repository Assurance Stack Means & Where It Is Useful

[← Back to Project README](../README.md) · [Documentation Hub](README.md) · [Architecture: OSCAL & Rego](ARCHITECTURE_OSCAL_AND_REGO.md)

---

## 1. Plain-English Summary: From Code Generator to Continuous ATO Stack

Rather than scattering security rules across static PDFs, Confluence pages, and ad-hoc prompts, the four-repository ecosystem answers the four questions every CISO, Authorizing Official (AO), and platform team asks before letting AI agents touch production APIs:

1. **What rules apply?** → **[`bsommers/security-controls`](https://github.com/bsommers/security-controls)** (NIST SP 800-53r5 Update 1 + 5 NIST COSIS AI/SI overlays).
2. **How do we engineer code so it doesn't break those rules?** → **[`bsommers/secure-design-patterns`](https://github.com/bsommers/secure-design-patterns)** (`MCP-001`–`MCP-008` + tested Python building blocks).
3. **How do we build servers fast without letting AI agents cheat the tests?** → **[`bsommers/forge`](https://github.com/bsommers/forge)** (locked Golden Template + 5-gate verifier + `--emit-oscal`).
4. **How do we prove compliance automatically on every commit and tool call?** → **[`bsommers/security-assurance`](https://github.com/bsommers/security-assurance)** *(this repo)* (OSCAL `1.1.2` SSP/SAR/POA&M + OPA/Rego policy gates).

---

## 2. Why It Is Relevant Right Now

- **Enterprise & Federal AI Governance Is Converging Here:** Regulated organizations (FedRAMP, DoD, financial services, healthcare) block MCP/agent rollouts when teams lack an **Authority to Operate (ATO)** trail around token passthrough, prompt injection, destructive actions, and reward-hacking coding agents.
- **Component Inheritance Solves `N Servers × 40 Controls`:** Inheriting ~80% of technical controls once from the locked Golden Template ([`component-definition-golden-template.json`](../oscal/component-definition-golden-template.json)) makes multi-server continuous ATO viable.
- **Separating Generative Authors from Deterministic Judges:** Enforced in [`ssp_gate.rego`](../policies/oscal/ssp_gate.rego): LLMs write tool code, **deterministic Python + Rego** decide pass/fail, partial gaps must sit in an explicit **POA&M** ([`poam-acme-incidents.json`](../oscal/poam-acme-incidents.json)), and organizational controls (`AT-3`, `PE-3`, `PM-9`, `PS-6`) cannot be rubber-stamped by an AI.

---

## 3. Candid Relevance Matrix

| Audience / Scenario | Useful Today? | Honest Caveat |
|---------------------|:-------------:|---------------|
| **Platform / AppSec teams rolling out internal MCP servers in regulated environments** | **High** | End-to-end Golden Template + dual-axis `32 KiB` bounding (`SC-5` closed in `forge v1.4.0`) + Stage 5 `--emit-oscal` + CI/runtime Rego PDPs. |
| **Reference architecture, customer demos & ATO reviews** | **High** | Executable proof (`pytest` + `opa test` green in CI) beats slideware, with remaining gaps (`POAM-FORGE-W5.2` host kernel sandboxing) tracked transparently. |
| **Solo developer wrapping a personal or hobby REST API** | **No (Overkill)** | Four repos, OSCAL UUID graphs, and Rego PDPs are heavy governance machinery when no compliance boundary or multi-tenant risk exists. |
