"""Server error page collection and analysis.

A PHP fatal-error page is a recon gift: it usually leaks the absolute server
path, every plugin/theme in the stack trace, and sometimes the security layer
that is blocking the scan (Wordfence's preventAuthorNScans is famous for it).
Instead of treating 5xx as noise, every response passing through
wpbuddy.httpclient is inspected; interesting ones are collected here and
analyzed once at the end of the scan.

Recorded when: status >= 500, or the body looks like a PHP error
(fatal/parse/uncaught + a .php reference - articles discussing errors are
not misclassified).
"""

import hashlib
import re
from collections import OrderedDict

MAX_BODY_SCAN = 200_000   # error pages are small; never scan huge bodies
MAX_ENTRIES = 10          # enough to characterize a site, keeps reports sane

FATAL_RE = re.compile(
    r"(Fatal error|Parse error|Uncaught|WordPress database error|Stack trace)", re.I)
# Real PHP error output has file:line structure; release notes merely
# MENTION the words "fatal error" (a changelog once got collected as an error
# page because of that).
ERROR_STRUCTURE_RE = re.compile(r"(?:on line \d+|:\d{2,}\s|Stack trace:|thrown in\s+.+\.php)", re.I)
PATH_RE = re.compile(r"(?<!\w)(/(?:home|var|usr|srv|opt|mnt|www|data|sites)/[A-Za-z0-9_./-]+\.php)")
PLUGIN_PATH_RE = re.compile(r"wp-content/plugins/([A-Za-z0-9_.\-]+)/")
THEME_PATH_RE = re.compile(r"wp-content/themes/([A-Za-z0-9_.\-]+)/")
AUTHOR_BLOCK_RE = re.compile(r"preventAuthorNScans|author\s+scan", re.I)

SECURITY_HINTS = {
    "wordfence": "Wordfence",
    "all-in-one-wp-security": "All In One WP Security",
    "better-wp-security": "iThemes Security",
    "ithemes-security": "iThemes Security",
    "sucuri": "Sucuri",
    "wp-simple-firewall": "Shield Security",
}

_seen = OrderedDict()


def inspect(resp):
    """Called by httpclient for every response; records interesting errors.

    Only responses from the scan target are collected - error pages from the
    vulnerability APIs the scanner also talks to are not the target's.
    """
    from .. import config
    from urllib.parse import urlsplit
    if resp is None:
        return
    if config.TARGET_HOST:
        host = (urlsplit(getattr(resp, "url", "") or "").hostname or "").lower()
        if host and host != config.TARGET_HOST:
            return
    status = getattr(resp, "status_code", 0) or 0
    body = (resp.text or "")[:MAX_BODY_SCAN]

    is_server_error = status >= 500
    looks_php_error = bool(FATAL_RE.search(body)) and ERROR_STRUCTURE_RE.search(body)
    if not is_server_error and not looks_php_error:
        return

    key = (status, hashlib.sha256("".join(body.split()).encode("utf-8", "replace")).hexdigest()[:12])
    if key in _seen:
        _seen[key]["count"] += 1
        return
    if len(_seen) >= MAX_ENTRIES:
        return

    _seen[key] = {
        "url": getattr(resp, "url", "") or "",
        "status": status,
        "count": 1,
        "plugins": sorted(set(PLUGIN_PATH_RE.findall(body))),
        "themes": sorted(set(THEME_PATH_RE.findall(body))),
        "paths": _root_prefixes(body),
        "notes": [f"security layer visible: {label}"
                  for hint, label in SECURITY_HINTS.items()
                  # only count a security layer when its plugin PATH appears in
                  # the trace, not when a changelog merely mentions its name
                  if re.search(rf"wp-content/plugins/{re.escape(hint)}/", body)]
                 + (["author-enumeration blocking is active"] if AUTHOR_BLOCK_RE.search(body) else []),
        "excerpt": _excerpt(body),
    }


WEB_ROOTS = {"public_html", "httpdocs", "htdocs", "www", "html", "web", "public", "public_http"}


def _root_prefixes(body):
    """Web-root directories (e.g. /home/user/public_html/) disclosed by paths."""
    roots = set()
    for match in PATH_RE.finditer(body):
        parts = match.group(1).split("/")
        for index, segment in enumerate(parts):
            if segment.lower() in WEB_ROOTS:
                roots.add("/".join(parts[:index + 1]) + "/")
                break
        else:
            if len(parts) >= 3:  # no known web root: fall back to a shallow prefix
                roots.add("/".join(parts[:3]) + "/")
    return sorted(roots)[:5]


def _excerpt(body):
    lines = [line.strip() for line in body.splitlines() if line.strip()][:3]
    return (" | ".join(lines))[:400]


def discovered_plugins():
    all_plugins = set()
    for entry in _seen.values():
        all_plugins.update(entry["plugins"])
    return all_plugins


def discovered_themes():
    all_themes = set()
    for entry in _seen.values():
        all_themes.update(entry["themes"])
    return all_themes


def entries():
    return list(_seen.values())


def reset():
    """Clear collected entries (used between scans/tests)."""
    _seen.clear()


def write_report(report, known_plugins=()):
    """Add the error-page section; best-effort CVE counts for newly revealed plugins."""
    if not _seen:
        return
    report.section("Server error pages (disclosure)")

    total = sum(e["count"] for e in _seen.values())
    discloses = any(e["paths"] or e["plugins"] or e["themes"] or e["notes"]
                    for e in _seen.values())
    if discloses:
        report.paragraph(f"{total} error response(s) were analyzed; PHP fatals leak internal "
                         f"structure even when the site looks opaque. Each distinct error page "
                         f"below discloses what it actually contains - server paths, active "
                         f"components, or defensive layers.")
    else:
        report.paragraph(f"{total} error response(s) were analyzed. None of them contained "
                         f"recognizable disclosure (no paths, component names or security "
                         f"layers) - the error handling is doing its job; only the responses "
                         f"themselves are noted.")

    for entry in _seen.values():
        again = f" (seen {entry['count']}x)" if entry["count"] > 1 else ""
        report.paragraph(f"**HTTP {entry['status']}** at `{entry['url']}`{again}:")
        report.bullets(
            [f"server path disclosed: `{p}`" for p in entry["paths"]]
            + [f"plugin in stack trace: **{p}**" for p in entry["plugins"]]
            + [f"theme in stack trace: **{t}**" for t in entry["themes"]]
            + [f"note: {n}" for n in entry["notes"]]
        )
        if entry["excerpt"]:
            report.code(entry["excerpt"])

    new_plugins = sorted(discovered_plugins() - set(known_plugins))
    if new_plugins:
        report.paragraph("Components revealed ONLY by error pages (not visible in normal "
                         "scanning) - version unknown, so CVE matching cannot filter by "
                         "version; database totals below:")
        from .. import vulndb
        for slug in new_plugins:
            try:
                vulns, db_status = vulndb.plugin_lookup(slug)
                if db_status != "ok":
                    known = "lookup failed (database unreachable)"
                elif vulns is None:
                    known = "not in the vulnerability database"
                else:
                    known = f"{len(vulns)} recorded vulnerabilities (any version)"
            except Exception:
                known = "lookup failed"
            report.bullets([f"**{slug}** - {known}"])

    report.paragraph("**Recommendation:** display_errors / WP_DEBUG should never be on in "
                     "production; error pages are free reconnaissance for attackers.")
