#!/usr/bin/env python3
"""Deterministic drift, Rego v1 hygiene, OSCAL completeness, and link verifier."""

from __future__ import annotations

import json
import re
import sys
import urllib.parse
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT / "src") not in sys.path:
    sys.path.insert(0, str(ROOT / "src"))

from security_assurance.compiler import compile_forge_assurance_bundle  # noqa: E402
from security_assurance.policy_sim import (  # noqa: E402
    evaluate_forge_manifest_guard,
    evaluate_oscal_ssp_gate,
)

MD_LINK_RE = re.compile(r"!?\[[^\]]*\]\(((?:[^()]|\([^()]*\))+)\)")


def _strip_fenced_code(md_text: str) -> str:
    return re.sub(r"```.*?```", "", md_text, flags=re.DOTALL)


def validate_repository(root: Path = ROOT) -> list[str]:
    errors: list[str] = []
    fixtures_dir = root / "fixtures" / "forge-acme-incidents"
    bundle = compile_forge_assurance_bundle(fixtures_dir)

    expected_files = {
        root / "oscal" / "component-definition-golden-template.json": (
            json.dumps(bundle.component_definition, indent=2) + "\n"
        ),
        root / "oscal" / "ssp-acme-incidents.json": json.dumps(bundle.ssp, indent=2) + "\n",
        root / "oscal" / "assessment-results-acme-incidents.json": (
            json.dumps(bundle.assessment_results, indent=2) + "\n"
        ),
        root / "oscal" / "poam-acme-incidents.json": json.dumps(bundle.poam, indent=2) + "\n",
        root / "docs" / "rendered" / "acme-incidents-SSP.md": bundle.markdown_ssp,
    }

    for path, expected_content in expected_files.items():
        if not path.is_file():
            errors.append(f"Missing generated artifact: {path.relative_to(root)}")
        elif path.read_text(encoding="utf-8") != expected_content:
            errors.append(
                f"Drift detected in {path.relative_to(root)} — run 'security-assurance build-all'"
            )

    # Verify Forge fixtures pass both policy gates
    manifest = json.loads((fixtures_dir / "forge-manifest.json").read_text(encoding="utf-8"))
    release = json.loads(
        (fixtures_dir / "forge-release-artifacts.json").read_text(encoding="utf-8")
    )
    for err in evaluate_forge_manifest_guard({"manifest": manifest, "release": release}):
        errors.append(f"Manifest policy deny: {err}")
    for err in evaluate_oscal_ssp_gate(
        {"ssp": bundle.ssp, "sar": bundle.assessment_results, "poam": bundle.poam}
    ):
        errors.append(f"OSCAL SSP gate deny: {err}")

    # Verify every Rego file declares package + import rego.v1 and has a companion _test.rego
    rego_files = sorted((root / "policies").rglob("*.rego"))
    if len(rego_files) < 6:
        errors.append(f"Expected >= 6 Rego policy/test files, found {len(rego_files)}")
    for rego in rego_files:
        text = rego.read_text(encoding="utf-8")
        if "package assurance." not in text:
            errors.append(f"{rego.relative_to(root)}: missing 'package assurance.*'")
        if "import rego.v1" not in text:
            errors.append(f"{rego.relative_to(root)}: missing 'import rego.v1'")
        if not rego.name.endswith("_test.rego"):
            companion = rego.with_name(rego.stem + "_test.rego")
            if not companion.is_file():
                errors.append(f"{rego.relative_to(root)}: missing unit test {companion.name}")

    # Verify zero broken relative links across Markdown docs
    for md_path in sorted(root.rglob("*.md")):
        if ".venv" in md_path.parts:
            continue
        cleaned = _strip_fenced_code(md_path.read_text(encoding="utf-8"))
        for match in MD_LINK_RE.finditer(cleaned):
            raw_target = match.group(1).strip()
            if not raw_target or raw_target.startswith(("#", "http://", "https://", "mailto:")):
                continue
            rel_part = urllib.parse.unquote(raw_target.split("#", 1)[0])
            if not rel_part:
                continue
            if not (md_path.parent / rel_part).resolve().exists():
                errors.append(
                    f"Broken relative link in {md_path.relative_to(root)}: '{raw_target}'"
                )

    return errors


def main() -> int:
    errors = validate_repository(ROOT)
    if errors:
        for err in errors:
            print(f"[FAIL] {err}", file=sys.stderr)
        return 1
    print(
        "[PASS] Verified 4 deterministic OSCAL 1.1.2 models (Component Def, SSP, SAR, POA&M), "
        "rendered SSP.md, and 3 Rego v1 policy suites."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
