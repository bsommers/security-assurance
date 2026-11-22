#!/usr/bin/env python3
"""Deterministic Tri-Gate Policy Conductor (OSCAL + OPA/Rego) SVG + PNG generator."""

from __future__ import annotations

import math
import shutil
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SANS = "system-ui, -apple-system, 'Segoe UI', Roboto, sans-serif"
MONO = "ui-monospace, 'Cascadia Code', 'Fira Code', Menlo, Consolas, monospace"


def _defs(prefix: str) -> str:
    return f"""  <defs>
    <linearGradient id="{prefix}-bg" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#070514"/>
      <stop offset="50%" stop-color="#140c2e"/>
      <stop offset="100%" stop-color="#060a18"/>
    </linearGradient>
    <linearGradient id="{prefix}-gold" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#fef08a"/>
      <stop offset="50%" stop-color="#fbbf24"/>
      <stop offset="100%" stop-color="#d97706"/>
    </linearGradient>
    <linearGradient id="{prefix}-seal" x1="0%" y1="0%" x2="100%" y2="100%">
      <stop offset="0%" stop-color="#00ff9d"/>
      <stop offset="100%" stop-color="#00e5ff"/>
    </linearGradient>
    <pattern id="{prefix}-grid" width="32" height="32" patternUnits="userSpaceOnUse">
      <path d="M 32 0 L 0 0 0 32" fill="none" stroke="#ff2a85"
            stroke-opacity="0.10" stroke-width="1"/>
      <circle cx="0" cy="0" r="1.3" fill="#00e5ff" fill-opacity="0.25"/>
    </pattern>
    <filter id="{prefix}-glow" x="-25%" y="-25%" width="150%" height="150%">
      <feGaussianBlur stdDeviation="5" result="blur"/>
      <feMerge>
        <feMergeNode in="blur"/>
        <feMergeNode in="SourceGraphic"/>
      </feMerge>
    </filter>
  </defs>"""


def _rotated_ellipse_poly(
    cx: float, cy: float, rx: float, ry: float, deg: float, steps: int = 72
) -> str:
    rad = math.radians(deg)
    cos_d, sin_d = math.cos(rad), math.sin(rad)
    pts: list[str] = []
    for i in range(steps):
        t = 2.0 * math.pi * i / steps
        ex, ey = rx * math.cos(t), ry * math.sin(t)
        px = cx + ex * cos_d - ey * sin_d
        py = cy + ex * sin_d + ey * cos_d
        pts.append(f"{px:.1f},{py:.1f}")
    return " ".join(pts)


def _emblem_group(cx: float, cy: float, scale: float, prefix: str) -> str:
    # Three interlocking gyroscopic policy rings (Cyan=OSCAL, Magenta=Rego, Gold=ATO)
    # converging on an Art-Deco emerald verification keystone check seal
    hex_pts: list[str] = []
    for i in range(6):
        ang = math.radians(-90 + i * 60)
        hx = cx + math.cos(ang) * 58 * scale
        hy = cy + math.sin(ang) * 58 * scale
        hex_pts.append(f"{hx:.1f},{hy:.1f}")

    c1x, c1y = cx - 22 * scale, cy + 2 * scale
    c2x, c2y = cx - 4 * scale, cy + 20 * scale
    c3x, c3y = cx + 26 * scale, cy - 16 * scale

    rx, ry = 132 * scale, 58 * scale
    ring_cyan = _rotated_ellipse_poly(cx, cy, rx, ry, -30.0)
    ring_magenta = _rotated_ellipse_poly(cx, cy, rx, ry, 30.0)
    ring_gold = _rotated_ellipse_poly(cx, cy, rx, ry, 90.0)

    return "\n".join(
        [
            "  <g>",
            f'    <circle cx="{cx:.1f}" cy="{cy:.1f}" r="{144 * scale:.1f}" fill="#0a0920" '
            f'fill-opacity="0.94" stroke="url(#{prefix}-gold)" stroke-width="{3.8 * scale:.1f}"/>',
            f'    <polygon points="{ring_cyan}" fill="none" stroke="#00e5ff" '
            f'stroke-width="{4.4 * scale:.1f}" filter="url(#{prefix}-glow)"/>',
            f'    <polygon points="{ring_magenta}" fill="none" stroke="#ff2a85" '
            f'stroke-width="{4.4 * scale:.1f}" filter="url(#{prefix}-glow)"/>',
            f'    <polygon points="{ring_gold}" fill="none" stroke="url(#{prefix}-gold)" '
            f'stroke-width="{4.4 * scale:.1f}"/>',
            f'    <polygon points="{" ".join(hex_pts)}" fill="#08162b" '
            f'stroke="url(#{prefix}-seal)" stroke-width="{4.2 * scale:.1f}" '
            f'filter="url(#{prefix}-glow)"/>',
            f'    <polyline points="{c1x:.1f},{c1y:.1f} {c2x:.1f},{c2y:.1f} {c3x:.1f},{c3y:.1f}" '
            f'fill="none" stroke="#00ff9d" stroke-width="{8.5 * scale:.1f}" '
            f'stroke-linecap="round" stroke-linejoin="round" filter="url(#{prefix}-glow)"/>',
            "  </g>",
        ]
    )


def build_square_icon_svg() -> str:
    return "\n".join(
        [
            '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512" '
            'width="512" height="512">',
            _defs("sa-sq"),
            '  <rect width="512" height="512" rx="92" fill="url(#sa-sq-bg)"/>',
            '  <rect width="512" height="512" rx="92" fill="url(#sa-sq-grid)"/>',
            '  <rect x="22" y="22" width="468" height="468" rx="74" fill="none" '
            'stroke="url(#sa-sq-gold)" stroke-width="4" stroke-opacity="0.85"/>',
            _emblem_group(256.0, 256.0, 1.44, "sa-sq"),
            "</svg>",
            "",
        ]
    )


def build_hero_banner_svg() -> str:
    # Jazzy harmonic resonance wave on right
    wave_pts: list[str] = []
    for idx in range(22):
        wx = 1005 + idx * 7
        wy = 140 + math.sin(idx * 0.75) * (24 if idx % 2 == 0 else 12)
        wave_pts.append(f"{wx:.1f},{wy:.1f}")

    return "\n".join(
        [
            '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1200 360" '
            'width="1200" height="360">',
            _defs("sa-hero"),
            '  <rect width="1200" height="360" rx="24" fill="url(#sa-hero-bg)"/>',
            '  <rect width="1200" height="360" rx="24" fill="url(#sa-hero-grid)"/>',
            '  <rect x="14" y="14" width="1172" height="332" rx="18" fill="none" '
            'stroke="url(#sa-hero-gold)" stroke-width="2.5" stroke-opacity="0.82"/>',
            '  <path d="M 30 54 L 30 30 L 66 30 M 1170 54 L 1170 30 L 1134 30 '
            'M 30 306 L 30 330 L 66 330 M 1170 306 L 1170 330 L 1134 330" '
            'fill="none" stroke="#ff2a85" stroke-width="3"/>',
            f'  <polyline points="{" ".join(wave_pts)}" fill="none" stroke="#ff2a85" '
            'stroke-width="2.6" stroke-opacity="0.7" filter="url(#sa-hero-glow)"/>',
            _emblem_group(196.0, 180.0, 1.02, "sa-hero"),
            f'  <text x="380" y="90" fill="#ff2a85" font-family="{MONO}" font-size="14" '
            'font-weight="700">TRI-GATE POLICY CONDUCTOR  //  CONTINUOUS ATO</text>',
            f'  <text x="378" y="152" fill="#f8fafc" font-family="{SANS}" font-size="48" '
            'font-weight="800">SECURITY ASSURANCE</text>',
            f'  <text x="380" y="196" fill="#94a3b8" font-family="{SANS}" font-size="19" '
            'font-weight="500">NIST OSCAL 1.1.2 System Security Plans, POA&amp;M &amp; '
            "OPA Rego v1 Gates</text>",
            '  <g transform="translate(380, 232)">',
            '    <rect width="198" height="40" rx="8" fill="#130d2e" '
            'stroke="#00e5ff" stroke-width="1.5"/>',
            f'    <text x="99" y="25" text-anchor="middle" fill="#00e5ff" font-family="{MONO}" '
            'font-size="13" font-weight="700">OSCAL 1.1.2 SSP + SAR</text>',
            "  </g>",
            '  <g transform="translate(592, 232)">',
            '    <rect width="192" height="40" rx="8" fill="#130d2e" '
            'stroke="#ff2a85" stroke-width="1.5"/>',
            f'    <text x="96" y="25" text-anchor="middle" fill="#ff2a85" font-family="{MONO}" '
            'font-size="13" font-weight="700">3 OPA REGO v1 PDPs</text>',
            "  </g>",
            '  <g transform="translate(798, 232)">',
            '    <rect width="224" height="40" rx="8" fill="#130d2e" '
            'stroke="#00ff9d" stroke-width="1.5"/>',
            f'    <text x="112" y="25" text-anchor="middle" fill="#00ff9d" font-family="{MONO}" '
            'font-size="13" font-weight="700">ZERO LLM SELF-GRADING</text>',
            "  </g>",
            f'  <text x="380" y="314" fill="#fde047" font-family="{MONO}" font-size="13">'
            "$ opa test -v policies/ &amp;&amp; security-assurance evaluate"
            "  -&gt;  [PASS] ATO ALLOW"
            "</text>",
            "</svg>",
            "",
        ]
    )


def _rasterize(svg_path: Path, png_path: Path, width: int) -> None:
    import tempfile

    magick = shutil.which("magick")
    if not magick:
        raise RuntimeError("ImageMagick 'magick' binary required to rasterize PNG assets.")
    clean = (
        svg_path.read_text(encoding="utf-8")
        .replace(f'font-family="{SANS}"', 'font-family="Helvetica"')
        .replace(f'font-family="{MONO}"', 'font-family="Menlo"')
    )
    with tempfile.NamedTemporaryFile(suffix=".svg", mode="w", encoding="utf-8") as tmp:
        tmp.write(clean)
        tmp.flush()
        cmd = [
            magick,
            "-font",
            "/System/Library/Fonts/Helvetica.ttc",
            "-background",
            "none",
            tmp.name,
            "-resize",
            f"{width}x",
            str(png_path),
        ]
        subprocess.run(cmd, check=True)  # noqa: S603


def main() -> int:
    sq = build_square_icon_svg()
    for rel_svg, rel_png in [
        ("assets/logo.svg", "assets/logo.png"),
        ("docs/assets/icon.svg", "docs/assets/icon.png"),
    ]:
        sp = ROOT / rel_svg
        pp = ROOT / rel_png
        sp.parent.mkdir(parents=True, exist_ok=True)
        sp.write_text(sq, encoding="utf-8")
        _rasterize(sp, pp, 512)

    hero_svg = ROOT / "docs" / "assets" / "logo.svg"
    hero_png = ROOT / "docs" / "assets" / "logo.png"
    hero_svg.write_text(build_hero_banner_svg(), encoding="utf-8")
    _rasterize(hero_svg, hero_png, 1200)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
