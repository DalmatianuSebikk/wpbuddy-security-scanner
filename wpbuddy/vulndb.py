"""Client for the wpvulnerability.net open API.

API notes (verified 2026-09):
- Endpoints: /core/{major.minor}/, /plugin/{slug}/, /theme/{slug}/ - all alive,
  same JSON schema the original project used.
- Unknown-but-valid slugs return 200 with data.vulnerability = null.
- Invalid slugs return 404 with {"error":1, "data":null} - callers must not
  assume `data` is a dict.
- The /core/{version}/ list contains every vulnerability AFFECTING that
  version (including ones fixed in later releases), so results are reported
  as-is: no local "is my version newer" filtering - that only created false
  negatives.
"""

from . import httpclient
from .versioning import compare_versions, major_minor

API_BASE = "https://www.wpvulnerability.net"


def _fetch(kind, slug):
    """Return the `data` dict for an endpoint, or None (unknown/error/unreachable)."""
    resp = httpclient.get(f"{API_BASE}/{kind}/{slug}/")
    if resp is None:
        return None
    try:
        payload = resp.json()
    except ValueError:
        return None
    if not isinstance(payload, dict) or payload.get("error"):
        return None
    data = payload.get("data")
    return data if isinstance(data, dict) else None


def core_vulnerabilities(version):
    data = _fetch("core", major_minor(version))
    if not data:
        return []
    return data.get("vulnerability") or []


def plugin_vulnerabilities(slug):
    data = _fetch("plugin", slug)
    if not data:
        return None  # None = nothing known about this slug, [] = known & clean
    return data.get("vulnerability") or []


def theme_vulnerabilities(slug):
    data = _fetch("theme", slug)
    if not data:
        return None
    return data.get("vulnerability") or []


def is_affected(installed_version, operator):
    """Apply a vulnerability `operator` object from the API to an installed version.

    Returns (affected: bool, basis: 'bounded' | 'unfixed' | 'assumed').
    Honours min_operator/min_version, max_operator/max_version and the
    `unfixed` flag (affects every version). Unknown/missing operators are
    treated as affected so we never silently drop a real finding - but the
    'assumed' basis lets the report label those findings as lower confidence.
    """
    if not operator:
        return True, "assumed"
    if str(operator.get("unfixed") or "0") == "1":
        return True, "unfixed"

    for bound_key, op_key in (("max_version", "max_operator"), ("min_version", "min_operator")):
        bound, op = operator.get(bound_key), operator.get(op_key)
        if not bound or not op:
            continue
        cmp = compare_versions(installed_version, bound)
        if op == "lt" and cmp >= 0:
            return False, "bounded"
        if op == "le" and cmp > 0:
            return False, "bounded"
        if op == "gt" and cmp <= 0:
            return False, "bounded"
        if op == "ge" and cmp < 0:
            return False, "bounded"
        if op == "eq" and cmp != 0:
            return False, "bounded"
    return True, "bounded"


def affected_vulnerabilities(installed_version, vulns):
    """Filter a raw API vulnerability list down to deduplicated, affected entries.

    Each entry carries the applicability 'basis' for the confidence layer.
    """
    out, seen = [], set()
    for vuln in vulns or []:
        affected, basis = is_affected(installed_version, vuln.get("operator"))
        if not affected:
            continue
        source = (vuln.get("source") or [{}])[0]
        name = source.get("name") or vuln.get("name") or "Unnamed issue"
        description = source.get("description") or ""
        # The same issue often arrives from several sources (CVE + WPScan +
        # Wordfence); dedupe on the description text, like the core scan intended.
        key = description or name
        if key in seen:
            continue
        seen.add(key)
        out.append({
            "name": name,
            "description": description,
            "link": source.get("link"),
            "severity": _severity(vuln),
            "basis": basis,
        })
    return out


def _severity(vuln):
    try:
        cvss = vuln["impact"]["cvss3"]
        return f"{cvss.get('score', '?')} ({cvss.get('severity', 'unknown')})"
    except (KeyError, TypeError):
        return None
