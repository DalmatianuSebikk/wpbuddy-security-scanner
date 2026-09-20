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

Upstream data hygiene, handled locally because the API sometimes serves
scraped garbage: advisory names that are really error-page titles ("404
Page Not Found") get replaced by their CVE id, and version bounds stated in
advisory TITLES ("<plugin> <= 7.5.0 - ...") are cross-checked against the
installed version - an 'unfixed' flag contradicted by its own title is
stale upstream data, kept in the report but demoted ('contradicted' basis).
"""

import os
import re
import time

from . import httpclient
from .versioning import compare_versions, major_minor

API_BASE = "https://www.wpvulnerability.net"

# Second source for CORE CVE applicability: NVD's CPE criteria carry explicit
# version ranges the wpvulnerability.net operator objects sometimes lack, so
# an 'assumed' finding can become bounded (or refuted). Unauthenticated NVD
# allows 5 requests / 30 s - set NVD_API_KEY to raise that.
NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_RATE_DELAY = 6.0
_nvd_cache = {}
_nvd_last_fetch = 0.0

# Advisory "names" that are actually scraped error/interstitial page titles.
_JUNK_NAME_RE = re.compile(
    r"^\s*(?:error|40[0-9]|50[0-9])\b|not found|access denied|just a moment|"
    r"attention required|forbidden", re.I)
_CVE_ID_RE = re.compile(r"(CVE-\d{4}-\d{4,})", re.I)

# Version bounds stated inside advisory titles ("... plugin <= 7.5.0 - ...").
_TITLE_MAX_LE = re.compile(r"(?:<=|≤|up to|through)\s*v?(\d+(?:\.\d+)+)", re.I)
_TITLE_MAX_LT = re.compile(r"(?:<|before|earlier than)\s*v?(\d+(?:\.\d+)+)", re.I)
_TITLE_EARLIER = re.compile(r"v?(\d+(?:\.\d+)+)\s*(?:and earlier|and below)", re.I)


def _clean_name(raw_name, link):
    """Replace error-page-title advisory names with their CVE id (or a placeholder)."""
    if not raw_name or not _JUNK_NAME_RE.search(raw_name):
        return raw_name or "Unnamed issue"
    cve = _CVE_ID_RE.search(link or "") or _CVE_ID_RE.search(raw_name)
    return (cve.group(1) if cve else "Unnamed advisory") + " (advisory title unreadable)"


def _title_contradicts(installed, name):
    """True when the advisory title's own version bound excludes `installed`.

    Titles like "Plugin <= 7.5.0 - Object Injection" carry the range the
    operator object sometimes lacks; when the flag says unfixed/assumed but
    the title bounds the issue below the installed version, the upstream
    entry is stale - the site is very likely already patched.
    """
    bound, op = None, None
    match = _TITLE_MAX_LE.search(name) or _TITLE_EARLIER.search(name)
    if match:
        bound, op = match.group(1), "le"
    else:
        match = _TITLE_MAX_LT.search(name)
        if match:
            bound, op = match.group(1), "lt"
    if not bound:
        return False
    cmp = compare_versions(installed, bound)
    return (op == "le" and cmp > 0) or (op == "lt" and cmp >= 0)


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
        link = source.get("link")
        name = _clean_name(source.get("name") or vuln.get("name"), link)
        if affected and basis != "bounded" and _title_contradicts(installed_version, name):
            basis = "contradicted"
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
            "link": link,
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


# ---------------------------------------------------------------- NVD enrichment

def enrich_core_with_nvd(version, affected):
    """Second-source check for core CVEs the API gave no range for.

    For every 'assumed' finding with a CVE id, NVD's CPE criteria are fetched
    (rate-limited, cached) and re-applied: an explicit range that INCLUDES the
    installed version turns the basis 'bounded'; one that EXCLUDES it marks
    the finding 'refuted' (kept in the report, heavily demoted - the scanner
    never silently drops anything). Any network/API failure keeps the
    original basis: the scan must not depend on a second database being up.
    """
    for vuln in affected or []:
        if vuln.get("basis") != "assumed":
            continue
        cve = _CVE_ID_RE.search(vuln.get("link") or "") or _CVE_ID_RE.search(vuln.get("name") or "")
        if not cve:
            continue
        cve_id = cve.group(1).upper()
        operator = _nvd_operator(cve_id)
        if not operator:
            continue
        hit, _ = is_affected(version, operator)
        vuln["basis"] = "bounded" if hit else "refuted"
        if not vuln.get("severity"):
            severity = _nvd_cache.get(f"severity:{cve_id}")
            if severity:
                vuln["severity"] = severity
    return affected


def _nvd_throttle():
    """Sleep just enough to stay inside NVD's unauthenticated rate window."""
    global _nvd_last_fetch
    elapsed = time.monotonic() - _nvd_last_fetch
    if elapsed < NVD_RATE_DELAY:
        time.sleep(NVD_RATE_DELAY - elapsed)
    _nvd_last_fetch = time.monotonic()


def _nvd_operator(cve_id):
    """Version-range operator for a WordPress-core CVE from NVD, or None.

    One fetch per CVE caches both the applicability operator and the CVSS
    severity string (used to fill findings the primary API left unscored).
    """
    if cve_id in _nvd_cache:
        return _nvd_cache[cve_id]
    _nvd_throttle()
    headers = {"apiKey": os.environ["NVD_API_KEY"]} if os.environ.get("NVD_API_KEY") else {}
    payload = None
    resp = httpclient.get(f"{NVD_API}?cveId={cve_id}", retries=1, headers=headers)
    if resp is not None and resp.status_code == 200:
        try:
            payload = resp.json()
        except ValueError:
            payload = None
    operator = _nvd_parse_operator(payload) if isinstance(payload, dict) else None
    severity = _nvd_severity(payload) if isinstance(payload, dict) else None
    _nvd_cache[cve_id] = operator
    if severity:
        _nvd_cache[f"severity:{cve_id}"] = severity
    return operator


def _nvd_parse_operator(payload):
    """Extract a {min,max}_version/{min,max}_operator dict from an NVD record.

    Only CPE criteria targeting wordpress:wordpress count - a CVE listing a
    plugin under the same id must not bound CORE applicability.
    """
    try:
        configs = payload["vulnerabilities"][0]["cve"]["configurations"]
    except (KeyError, IndexError, TypeError):
        return None
    for conf in configs or []:
        for node in conf.get("nodes", []) or []:
            for match in node.get("cpeMatch", []) or []:
                criteria = match.get("criteria", "")
                if "a:wordpress:wordpress" not in criteria:
                    continue
                operator = {}
                if match.get("versionStartIncluding"):
                    operator["min_version"] = match["versionStartIncluding"]
                    operator["min_operator"] = "ge"
                if match.get("versionStartExcluding"):
                    operator["min_version"] = match["versionStartExcluding"]
                    operator["min_operator"] = "gt"
                if match.get("versionEndIncluding"):
                    operator["max_version"] = match["versionEndIncluding"]
                    operator["max_operator"] = "le"
                if match.get("versionEndExcluding"):
                    operator["max_version"] = match["versionEndExcluding"]
                    operator["max_operator"] = "lt"
                exact = re.search(r"a:wordpress:wordpress:(\d+(?:\.\d+)*)", criteria)
                if not operator and exact:
                    operator = {"min_version": exact.group(1), "min_operator": "ge",
                                "max_version": exact.group(1), "max_operator": "le"}
                if operator:
                    return operator
    return None


def _nvd_severity(payload):
    """CVSS score/severity string from an NVD record, or None."""
    try:
        metrics = payload["vulnerabilities"][0]["cve"]["metrics"]
        cvss = (metrics.get("cvssMetricV31") or metrics.get("cvssMetricV30")
                or metrics.get("cvssMetricV2"))[0]["cvssData"]
        return f"{cvss.get('baseScore', '?')} ({str(cvss.get('baseSeverity', '?')).lower()})"
    except (KeyError, IndexError, TypeError, AttributeError):
        return None
