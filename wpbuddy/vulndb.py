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
# Phrase-tightened: "Error Log Viewer <= 2.1 - XSS" is a real advisory name
# and must survive - only actual error-page shapes count as junk.
_JUNK_NAME_RE = re.compile(
    r"^\s*(?:40[0-9]|50[0-9])\b|^\s*error\s*(?:page|code)?\s*$"
    r"|not found|access denied|just a moment|attention required|forbidden", re.I)
_CVE_ID_RE = re.compile(r"(CVE-\d{4}-\d{4,})", re.I)

# Version bounds stated in advisory titles AND descriptions. Descriptions
# matter as much as titles: the Complianz advisories carry "<= 7.5.0" only in
# the description body, and core advisories list whole range sets
# ("7.1 before 7.1.1; 7.0 through 7.0.4; ...").
_V = r"v?(\d+(?:\.\d+)+)"
_LE_BOUNDS = re.compile(
    rf"(?:<=|&lt;=|≤|up to|through)\s*{_V}"
    rf"|{_V}\s*(?:and earlier|and below)"
    rf"|\d+(?:\.\d+)+\s*(?:through|-|to)\s*{_V}", re.I)
_LT_BOUNDS = re.compile(rf"(?:<|&lt;|before|prior to|earlier than)\s*{_V}", re.I)


def _upper_bounds(text):
    """[(bound, 'le'|'lt'), ...] - every upper version bound stated in `text`."""
    # the bound can land in any of the alternation's capture groups
    out = [(next(g for g in m.groups() if g), "le")
           for m in _LE_BOUNDS.finditer(text or "")]
    out += [(m.group(1), "lt") for m in _LT_BOUNDS.finditer(text or "")]
    return out


def _url_bounds(url, slug):
    """Version bounds encoded in advisory URLs right after the component slug.

    Wordfence marks the affected ceiling in the slug with dots STRIPPED
    ('...-custom-post-order-313-...' = 3.1.3); Patchstack keeps dots
    ('...-2.0.1-...'), some feeds use dashes ('3-1-3'). Dotted/dashed forms
    become ordinary 'le' bounds; dashless digit runs get the 'digits'
    comparison (installed with dots stripped, compared as integers) - safe
    because a missed contradiction is recoverable but a manufactured one
    is not. Numbers not anchored to the slug (ids, years) never match.
    """
    if not url or not slug:
        return []
    bounds = []
    for m in re.finditer(rf"(?:^|[/._-]){re.escape(slug)}[-_](\d+(?:[-.]\d+)*)(?=[-/_]|$)", url):
        token = m.group(1)
        if "-" in token or "." in token:
            bounds.append((token.replace("-", "."), "le"))
        else:
            bounds.append((token, "digits"))
    return bounds


def _clean_name(raw_name, link):
    """Replace error-page-title advisory names with their CVE id (or a placeholder)."""
    if not raw_name or not _JUNK_NAME_RE.search(raw_name):
        return raw_name or "Unnamed issue"
    cve = _CVE_ID_RE.search(link or "") or _CVE_ID_RE.search(raw_name)
    return (cve.group(1) if cve else "Unnamed advisory") + " (advisory title unreadable)"


def _fetch(kind, slug):
    """Return `(data dict or None, status)` for an endpoint.

    status: 'ok' (API answered), 'not-found' (definitive answer: unknown
    slug), 'unreachable' (transport/JSON/API failure). A caller must never
    read an outage as an empty result - "site is clean" off a dead API is
    the worst failure mode this module has (P0-4).
    """
    resp = httpclient.get(f"{API_BASE}/{kind}/{slug}/")
    if resp is None:
        return None, "unreachable"
    try:
        payload = resp.json()
    except ValueError:
        return None, "unreachable"
    if not isinstance(payload, dict) or payload.get("error"):
        return None, "not-found"
    data = payload.get("data")
    if not isinstance(data, dict):
        return None, "not-found"
    return data, "ok"


def _lookup(kind, slug):
    """_fetch() with normalization for stubbed/legacy return shapes.

    Tests (and anything else) may stub `_fetch` with a bare dict (pre-P0-4
    shape, meaning 'the API answered this') or None (meaning failure); real
    calls return the (data, status) tuple above. All three are understood
    so a None stub can never be misread as a clean lookup.
    """
    result = _fetch(kind, slug)
    if isinstance(result, tuple):
        return result
    return (result, "ok") if isinstance(result, dict) else (None, "unreachable")


def core_lookup(version):
    """(vulnerability list or None, status) for a core version.

    None + status != 'ok': the lookup failed; None must not be reported as
    'no vulnerabilities'.
    """
    data, status = _lookup("core", major_minor(version))
    if status != "ok":
        return None, status
    return data.get("vulnerability") or [], "ok"


def core_vulnerabilities(version):
    """Back-compat wrapper: the list, or None when the lookup failed."""
    vulns, _ = core_lookup(version)
    return vulns


def plugin_lookup(slug):
    """(vulnerability list or None, status) for a plugin slug."""
    data, status = _lookup("plugin", slug)
    if status != "ok":
        return None, status
    return data.get("vulnerability") or [], "ok"


def plugin_vulnerabilities(slug):
    """Back-compat wrapper: None = unknown slug or failed lookup, [] = clean."""
    vulns, _ = plugin_lookup(slug)
    return vulns


def theme_lookup(slug):
    """(vulnerability list or None, status) for a theme slug."""
    data, status = _lookup("theme", slug)
    if status != "ok":
        return None, status
    return data.get("vulnerability") or [], "ok"


def theme_vulnerabilities(slug):
    vulns, _ = theme_lookup(slug)
    return vulns


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


def affected_vulnerabilities(installed_version, vulns, slug=None):
    """Filter a raw API vulnerability list down to deduplicated, affected entries.

    Each entry carries the applicability 'basis' for the confidence layer.
    `slug` enables the URL-bound cross-check (advisory links often encode the
    affected ceiling after the component slug).
    """
    out, seen = [], set()
    for vuln in vulns or []:
        affected, basis = is_affected(installed_version, vuln.get("operator"))
        if not affected:
            continue
        source = (vuln.get("source") or [{}])[0]
        link = source.get("link")
        name = _clean_name(source.get("name") or vuln.get("name"), link)
        description = source.get("description") or ""
        if affected and basis != "bounded":
            bounds = (_upper_bounds(name) + _upper_bounds(description)
                      + _url_bounds(link, slug))

            def excluded(bound, op):
                if op == "digits":
                    try:
                        return int(installed_version.replace(".", "")) > int(bound)
                    except ValueError:
                        return False
                cmp = compare_versions(installed_version, bound)
                return cmp > 0 if op == "le" else cmp >= 0

            if bounds and all(excluded(bound, op) for bound, op in bounds):
                basis = "contradicted"
            elif bounds and basis == "assumed":
                # the advisory's own range INCLUDES the installed version -
                # that is a real bound, not an assumption (P1-1). 'unfixed'
                # findings keep their (slightly lower) flag: the advisory
                # explicitly claims all versions are affected.
                basis = "bounded"
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
        operators = _nvd_operator(cve_id)
        if not operators:
            continue
        results = [is_affected(version, operator) for operator in operators]
        # ANY range including the version bounds the finding; only when EVERY
        # range excludes it is the finding refuted - a CVE with disjoint ranges
        # (< 6.5.0 and 6.6.0-6.7.0) must not be decided by its first entry (P0-5)
        if any(hit for hit, _ in results):
            vuln["basis"] = "bounded"
        else:
            vuln["basis"] = "refuted"
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
    """List of version-range operators for a WordPress-core CVE from NVD, or None.

    One fetch per CVE caches both the applicability operators and the CVSS
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
    """List of {min,max}_version/{min,max}_operator dicts from an NVD record.

    ALL CPE criteria targeting wordpress:wordpress are collected: a CVE can
    carry several disjoint ranges (< 6.5.0 and 6.6.0-6.7.0), and deciding by
    the first entry alone once refuted an installed version the second range
    clearly covers (P0-5). CPE for plugins under the same CVE are still
    ignored - they must not bound CORE applicability.
    """
    try:
        configs = payload["vulnerabilities"][0]["cve"]["configurations"]
    except (KeyError, IndexError, TypeError):
        return None
    operators = []
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
                    operators.append(operator)
    return operators or None


def _nvd_severity(payload):
    """CVSS score/severity string from an NVD record, or None."""
    try:
        metrics = payload["vulnerabilities"][0]["cve"]["metrics"]
        cvss = (metrics.get("cvssMetricV31") or metrics.get("cvssMetricV30")
                or metrics.get("cvssMetricV2"))[0]["cvssData"]
        return f"{cvss.get('baseScore', '?')} ({str(cvss.get('baseSeverity', '?')).lower()})"
    except (KeyError, IndexError, TypeError, AttributeError):
        return None
