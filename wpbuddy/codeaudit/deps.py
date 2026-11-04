"""Bundled-dependency SCA for gathered component sources (F-6).

Plugins routinely ship entire vendor trees; a fully patched plugin can
still bundle a library with a famous RCE. This scans the manifests in the
source the audit phase already gathered: composer.lock / package.json.

The advisory table is deliberately tiny and curated - every entry is a
well-documented, unambiguous fix boundary. It is plain data so extending
it is trivial; a real OSV feed is future work (see the design note).
"""

import json
import re
from pathlib import Path

from ..versioning import compare_versions

# package -> (first fixed version, what's wrong below it)
# Extend as plain data; keep every entry verifiable.
ADVISORIES = {
    "phpmailer/phpmailer": ("5.2.27", "CVE-2016-10045 / -10033 argument-injection RCE"),
    "guzzlehttp/guzzle": ("6.2.1", "CVE-2016-5385 'httpoxy' request forgery"),
    "guzzlehttp/psr7": ("1.9.1", "CVE-2022-24775 header injection (1.x branch)"),
}

_EXACT_VERSION_RE = re.compile(r"^v?\d+(?:\.\d+)+(?:[-.][\w.]+)?$")


def _normalize(version):
    return str(version or "").strip().lstrip("vV")


def scan(root, max_packages=60):
    """(inventory, advisories) for the manifests under `root`.

    inventory: [(package, version, source_manifest)] sorted
    advisories: [{package, installed, fixed_in, why}]
    """
    root = Path(root)
    inventory, advisories = [], []
    for manifest in sorted(root.rglob("composer.lock"))[:20]:
        try:
            payload = json.loads(manifest.read_text(encoding="utf-8", errors="replace"))
        except (ValueError, OSError):
            continue
        for section in ("packages", "packages-dev"):
            for pkg in payload.get(section) or []:
                if not isinstance(pkg, dict):
                    continue
                name, version = pkg.get("name", ""), _normalize(pkg.get("version"))
                if name and version:
                    inventory.append((name, version, manifest.name))
    for manifest in sorted(root.rglob("package.json"))[:20]:
        try:
            payload = json.loads(manifest.read_text(encoding="utf-8", errors="replace"))
        except (ValueError, OSError):
            continue
        for name, version in (payload.get("dependencies") or {}).items():
            version = _normalize(version)
            if not version:
                continue
            # ranges are inventoried (they name the dependency) but never
            # matched against a fix boundary - only pins can be
            inventory.append((name, version, manifest.name))

    inventory.sort()
    for name, version, _src in inventory[:max_packages]:
        if name.lower() in ADVISORIES and version and _EXACT_VERSION_RE.match(version):
            fixed_in, why = ADVISORIES[name.lower()]
            try:
                below = compare_versions(version, fixed_in) < 0
            except (TypeError, ValueError):
                below = False
            if below:
                advisories.append({"package": name, "installed": version,
                                   "fixed_in": fixed_in, "why": why})
    return inventory, advisories


def report_dependencies(report, label, inventory, advisories):
    """Render the inventory + advisories for one audited component."""
    if not inventory and not advisories:
        return
    if advisories:
        print(f"[!] Bundled dependencies with known vulnerabilities in {label}: "
              + ", ".join(a["package"] for a in advisories))
        report.paragraph(f"**Bundled dependencies with known vulnerabilities** (shipped "
                         f"inside {label}):")
        report.bullets([f"**{a['package']} {a['installed']}** - {a['why']}; fixed in "
                        f"**{a['fixed_in']}** - update the PARENT component (vendored "
                        f"copies only change with it)" for a in advisories])
    if inventory:
        shown = ", ".join(f"`{name} {version}`" for name, version, _ in inventory[:20])
        more = f" (+{len(inventory) - 20} more)" if len(inventory) > 20 else ""
        report.paragraph(f"Bundled third-party packages in {label} (supply-chain surface, "
                         f"from the shipped manifests): {shown}{more}.")
