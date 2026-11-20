"""CLI to compile OSCAL 1.1.2 SSP bundles and run continuous assurance policy checks."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from security_assurance.compiler import compile_forge_assurance_bundle
from security_assurance.policy_sim import (
    evaluate_forge_manifest_guard,
    evaluate_oscal_ssp_gate,
)


def default_root() -> Path:
    return Path(__file__).resolve().parent.parent.parent


def write_bundle(root: Path) -> None:
    fixtures_dir = root / "fixtures" / "forge-acme-incidents"
    bundle = compile_forge_assurance_bundle(fixtures_dir)

    oscal_dir = root / "oscal"
    oscal_dir.mkdir(parents=True, exist_ok=True)
    rendered_dir = root / "docs" / "rendered"
    rendered_dir.mkdir(parents=True, exist_ok=True)

    (oscal_dir / "component-definition-golden-template.json").write_text(
        json.dumps(bundle.component_definition, indent=2) + "\n",
        encoding="utf-8",
    )
    (oscal_dir / "ssp-acme-incidents.json").write_text(
        json.dumps(bundle.ssp, indent=2) + "\n",
        encoding="utf-8",
    )
    (oscal_dir / "assessment-results-acme-incidents.json").write_text(
        json.dumps(bundle.assessment_results, indent=2) + "\n",
        encoding="utf-8",
    )
    (oscal_dir / "poam-acme-incidents.json").write_text(
        json.dumps(bundle.poam, indent=2) + "\n",
        encoding="utf-8",
    )
    (rendered_dir / "acme-incidents-SSP.md").write_text(
        bundle.markdown_ssp,
        encoding="utf-8",
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="security-assurance")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("build-all", help="Deterministically compile OSCAL 1.1.2 JSON + Markdown SSP.")
    sub.add_parser("evaluate", help="Evaluate manifest_guard and ssp_gate policies against Forge.")
    args = parser.parse_args(argv)

    root = default_root()
    fixtures_dir = root / "fixtures" / "forge-acme-incidents"

    if args.command == "build-all":
        write_bundle(root)
        print(
            "Compiled 4 OSCAL 1.1.2 JSON models in oscal/ and docs/rendered/acme-incidents-SSP.md"
        )
        return 0

    if args.command == "evaluate":
        manifest = json.loads((fixtures_dir / "forge-manifest.json").read_text(encoding="utf-8"))
        release = json.loads(
            (fixtures_dir / "forge-release-artifacts.json").read_text(encoding="utf-8")
        )
        bundle = compile_forge_assurance_bundle(fixtures_dir)

        manifest_denies = evaluate_forge_manifest_guard({"manifest": manifest, "release": release})
        ssp_denies = evaluate_oscal_ssp_gate(
            {"ssp": bundle.ssp, "sar": bundle.assessment_results, "poam": bundle.poam}
        )
        summary = {
            "manifest_guard_allow": len(manifest_denies) == 0,
            "manifest_guard_denies": manifest_denies,
            "oscal_ssp_gate_allow": len(ssp_denies) == 0,
            "oscal_ssp_gate_denies": ssp_denies,
        }
        print(json.dumps(summary, indent=2))
        return 0 if not manifest_denies and not ssp_denies else 1

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
