"""File- and header-based passive checks.

- robots.txt content
- security headers: the interesting finding is what's MISSING, so missing
  hardening headers are reported as issues (the old version only echoed the
  ones present)
- sensitive/leaky files that should never be web-readable (all GET-only)

Sensitive-file existence is NOT judged by status code alone: many hosts answer
unknown URLs with a 200 'soft 404' (catch-all rewrites, error-page redirects),
and WAFs serve their challenge interstitials with HTTP 200 too (a Cloudflare
"One moment, please..." page once made every probe look like an exposure).
The check therefore:
1. learns the site's not-found signature from random nonexistent paths
2. does not follow redirects (a redirect to the homepage is not a file)
3. verifies content signatures before claiming anything is CONFIRMED -
   a wp-config backup contains DB_PASSWORD, a dump contains INSERT INTO, ...
4. treats bodies that say "not found"/"checking your browser"/"one moment"
   as absent regardless of status code and byte length (dynamic challenge
   pages drift by ~100 bytes between requests, which defeats any exact match)
"""

import hashlib
import random
import re
import string
from urllib.parse import urlsplit

from .. import httpclient

LISTING_MARKER = "Index of /"

# header -> short explanation of what its absence allows
SECURITY_HEADERS = {
    "Strict-Transport-Security": "forces HTTPS, blocks SSL-strip/downgrade",
    "Content-Security-Policy": "mitigates XSS and content injection",
    "X-Frame-Options": "clickjacking protection (combined with CSP frame-ancestors)",
    "X-Content-Type-Options": "prevents MIME-type sniffing",
    "Referrer-Policy": "limits URL leakage to third parties",
}

# path -> why it matters (checked as-is under the target root)
SENSITIVE_FILES = {
    "readme.html": "default WordPress readme leaks the core version",
    "wp-config.php.bak": "backed-up wp-config may contain DB credentials",
    "wp-config.php~": "editor backup of wp-config may contain DB credentials",
    "wp-config.php.save": "saved copy of wp-config may contain DB credentials",
    "wp-config.php.old": "renamed old wp-config may contain DB credentials",
    "wp-config.php.orig": "original wp-config copy may contain DB credentials",
    ".env": "environment files often hold secrets (DB, SMTP, API keys)",
    "wp-content/debug.log": "debug log leaks paths, users, sometimes secrets",
    ".git/HEAD": "exposed Git repository allows full source recovery",
    "wp-content/uploads/dump.sql": "database dump in uploads",
    "wp-content/backups/": "backup folder - directory listing may expose archives",
    "backup.zip": "site backup archive in the web root",
    "wordpress.zip": "WordPress archive in the web root",
    "db.sql": "database dump in the web root",
    "phpinfo.php": "phpinfo() disclosure (PHP version, modules, paths)",
    ".htpasswd": "HTTP basic-auth password file (crackable hashes)",
}

# Binary artifacts identified by magic bytes instead of a text regex
# (a ZIP served as 200 is an archive no matter what the HTML says).
MAGIC_SIGNATURES = {
    "backup.zip": (b"PK\x03\x04", "ZIP archive"),
    "wordpress.zip": (b"PK\x03\x04", "ZIP archive"),
}

# path -> (content regex, what matching content proves). A 200 alone proves
# nothing on soft-404 servers; these signatures turn 'reachable' into
# 'CONFIRMED exposed' with evidence. Secrets are never echoed into the report.
CONTENT_SIGNATURES = {
    "wp-config.php.bak": (r"DB_PASSWORD|DB_NAME|table_prefix", "WordPress DB credentials"),
    "wp-config.php~": (r"DB_PASSWORD|DB_NAME|table_prefix", "WordPress DB credentials"),
    "wp-config.php.save": (r"DB_PASSWORD|DB_NAME|table_prefix", "WordPress DB credentials"),
    "wp-config.php.old": (r"DB_PASSWORD|DB_NAME|table_prefix", "WordPress DB credentials"),
    "wp-config.php.orig": (r"DB_PASSWORD|DB_NAME|table_prefix", "WordPress DB credentials"),
    ".env": (r"(?m)^[A-Z0-9_]{2,}\s*=", "environment variable definitions"),
    "wp-content/debug.log": (r"PHP (?:Notice|Warning|Fatal error|Deprecated|Parse error)",
                             "PHP debug output"),
    "wp-content/uploads/dump.sql": (r"CREATE TABLE|INSERT INTO|MySQL dump", "SQL dump content"),
    "db.sql": (r"CREATE TABLE|INSERT INTO|MySQL dump", "SQL dump content"),
    ".git/HEAD": (r"ref:\s*refs/", "git repository metadata"),
    "readme.html": (r"Version\s+\d", "WordPress version disclosure"),
    "wp-content/backups/": (re.escape(LISTING_MARKER), "directory listing"),
    "phpinfo.php": (r"phpinfo\s*\(\)|PHP Version</|phpinfo\(\)", "phpinfo() output page"),
    ".htpasswd": (r"(?m)^\S+:(?:\$apr1\$|\$2y?\$|\$P\$|[A-Za-z0-9./]{13})",
                  "htpasswd credential hashes"),
}


# Bodies that say "this is not the page you asked for" whatever the status
# code claims: soft-404 articles, error pages, and WAF/CDN interstitials
# ("One moment, please...", "Checking your browser..."). Only consulted AFTER
# a content signature failed to match, so a real file whose text merely
# mentions these words is never suppressed.
NOT_FOUND_MARKERS = re.compile(
    r"not found|nothing (?:here|found)|error 40[0-9]|404 (?:page|error)|"
    r"one moment, please|just a moment|checking your browser|attention required|"
    r"access denied|request blocked|are you a robot|"
    r"verify (?:that )?you (?:are|re) human|"
    r"(?:has been|was) (?:removed|moved|deleted)|no longer (?:available|exists)",
    re.I)

# how much of a body the marker check needs to see (interstitials front-load
# their titles; scanning more just wastes time on big pages)
MARKER_SCAN_BYTES = 4000

# Error/challenge pages announce themselves by shape: HTML document structure
# up front, a tiny body, or a non-2xx status. Only error-shaped bodies get
# the marker scan - a real readme/changelog is plain text that can legitimately
# mention "link not found fixed" without being an error page (P1-3).
ERROR_PAGE_SHAPE_RE = re.compile(r"<\s*(?:!doctype\s+html|html|head|title)\b", re.I)
ERROR_SHAPE_MAX_BYTES = 1500


def check_headers(report, target):
    report.section("HTTP security headers")
    resp = httpclient.get(target)
    if resp is None:
        report.paragraph("Could not fetch the homepage to inspect headers.")
        return

    # HSTS is defined for HTTPS transport only - a browser never applies it
    # to a plain-HTTP origin, so demanding it there is noise (P1-4). The
    # expected set is therefore built per scheme.
    https = (urlsplit(target).scheme or "http").lower() == "https"
    expected = dict(SECURITY_HEADERS)
    if not https:
        del expected["Strict-Transport-Security"]

    missing = [h for h in expected if h not in resp.headers]
    present = [h for h in expected if h in resp.headers]

    if missing:
        print(f"[!] Missing security headers: {', '.join(missing)}")
        report.paragraph("The following hardening headers are **missing** (each is a low-severity "
                         "finding on its own; together they mean the site relies purely on "
                         "application-level defenses):")
        report.bullets([f"**{h}** - {why}" for h, why in expected.items() if h in missing])
    if present:
        report.paragraph("Headers already present:")
        report.bullets([f"**{h}**: {resp.headers[h]}" for h in present])
    if not https:
        report.paragraph("`Strict-Transport-Security` is not listed above because the scan ran "
                         "over plain HTTP - browsers only honour HSTS on HTTPS responses. Moving "
                         "the site to HTTPS (then adding HSTS) is the recommendation.")

    for leak in ("Server", "X-Powered-By"):
        if leak in resp.headers:
            value = resp.headers[leak]
            print(f"[*] Info leak: {leak}: {value}")
            report.paragraph(f"Technology disclosure: **{leak}: {value}**")


# Entries virtually every WordPress site ships (Yoast/defaults) - not findings
BORING_DISALLOWS = {
    "/wp-admin/", "/wp-admin-admin/", "/wp-login.php", "/wp-json/", "/?rest_route=",
    "/xmlrpc.php", "/wp-register.php", "/feed", "/trackback", "/comments",
    "/search", "/*?", "*?s=", "/cgi-bin/", "/wp-content/plugins/", "/readme.html",
}


def check_robots(report, target):
    report.section("robots.txt")
    resp = httpclient.get(f"{target}robots.txt")
    if resp is None or resp.status_code >= 400:
        report.paragraph("robots.txt not found (or unreachable).")
        return

    print("[*] robots.txt found")
    report.paragraph(f"robots.txt was found: {target}robots.txt")
    report.code(resp.text.strip())

    # Paths disallowed in robots.txt are prime audit targets: admin panels,
    # staging areas, backups - exactly what the owner wants hidden from Google
    # (after filtering the WordPress/Yoast defaults every site ships).
    # [ \t]* (not \s*) so an EMPTY 'Disallow:' can't swallow the newline and
    # capture the next line's first word ("Sitemap:" was once 'interesting').
    disallowed = sorted(set(re.findall(r"(?im)^disallow:[ \t]*(\S+)", resp.text)))
    interesting = [d for d in disallowed if d.lower() not in BORING_DISALLOWS]
    if interesting:
        report.paragraph("Interesting `Disallow` entries (hidden-but-public paths worth reviewing; "
                         "standard WordPress/Yoast defaults omitted):")
        report.bullets(interesting)


def check_sensitive_files(report, target):
    report.section("Sensitive file exposure")
    baseline = soft404_baseline(target)
    if baseline:
        print(f"[*] Soft-404 server detected (unknown paths answer "
              f"{baseline['status']} with {baseline['length']} bytes); "
              f"status codes alone won't be trusted")

    # Blanket-deny detection: WAFs/webservers often 403 whole path *patterns*
    # (.env, .git, wp-config.*) regardless of existence. If an obviously bogus
    # name is denied too, 403s here carry no existence signal at all.
    bogus = f"wp-config.php.bak-wpbuddy-{random.randrange(1 << 30):x}"
    blanket_probe = httpclient.get(target + bogus, allow_redirects=False)
    blanket_deny = blanket_probe is not None and blanket_probe.status_code in (401, 403)

    exposed, unsure, protected = [], [], []
    for path, why in SENSITIVE_FILES.items():
        resp = httpclient.get(target + path, allow_redirects=False)
        if resp is None:
            continue
        verdict, detail = _classify(path, resp, baseline, target)
        if verdict == "absent":
            continue
        entry = (path, why, detail)
        if verdict == "confirmed":
            exposed.append(entry)
            print(f"[!] CONFIRMED exposed - {path}: {detail}")
        elif verdict == "reachable":
            unsure.append(entry)
            print(f"[?] Reachable (200) but content unrecognized - {path}; verify manually")
        elif verdict == "protected":
            protected.append(entry)
            if not blanket_deny:
                print(f"[*] {path} answered {detail} - may exist but is protected")

    for path, why, detail in exposed:
        report.paragraph(f"**CONFIRMED exposed: `{path}`** - content matches {detail}. {why}. "
                         f"This is a real exposure, not a status-code guess.")
    for path, why, detail in unsure:
        report.paragraph(f"`{path}` answered HTTP 200 with unexpected content ({detail}) and "
                         f"did not match the site's not-found signature - possible exposure, "
                         f"verify manually. {why}.")
    if protected:
        if blanket_deny:
            report.paragraph(f"The server denies these paths wholesale (a made-up filename "
                             f"`{bogus}` was denied the same way), which is good hardening "
                             f"but means the 403/401s below are NOT evidence the files exist: "
                             + ", ".join(f"`{p}`" for p, _, _ in protected))
        else:
            for path, why, detail in protected:
                report.paragraph(f"`{path}` answered {detail} (access denied) - often means "
                                 f"the file exists behind a rule. {why}.")
    if not (exposed or unsure):
        report.paragraph("None of the common sensitive files (wp-config backups, .env, "
                         "debug.log, .git, dumps) are readable.")


# ---------------------------------------------------------------- soft-404 handling

def _body_fingerprint(resp):
    body = resp.text or ""
    normalized = "".join(body.split()).encode("utf-8", "replace")
    return hashlib.sha256(normalized).hexdigest()[:16]


def _similar_length(a, b):
    """True when two body lengths can be the same dynamic page.

    Challenge/error pages embed per-request tokens (ray ids, timestamps) that
    shift the size by a ~hundred bytes; an exact or near-exact match (the old
    +/-48 bytes) let every probe on such a site look distinct. Within 5% of
    the page (floor 64 bytes) counts as the same page.
    """
    return abs(a - b) <= max(64, min(a, b) // 20)


def _soft404_baseline(target):
    """Learn how this site says 'not found'.

    Probes two random nonexistent paths. If both answer with the same status
    and an identical (or byte-similar - dynamic pages drift) body, that
    signature is the site's soft-404 and any candidate response matching it
    means 'absent', no matter the status code. Returns None for sites with
    honest 404s (then status codes are trusted).
    """
    signatures = []
    for _ in range(2):
        junk = "wpbuddy-" + "".join(random.choices(string.ascii_lowercase, k=12)) + ".html"
        resp = httpclient.get(target + junk, allow_redirects=False)
        if resp is None:
            return None
        if resp.status_code == 404:
            return None
        signatures.append({
            "status": resp.status_code,
            "hash": _body_fingerprint(resp),
            "length": len(resp.content),
            "redirect": resp.headers.get("Location", "") if resp.status_code // 100 == 3 else "",
        })
    first, second = signatures
    if first["status"] != second["status"] or first["redirect"] != second["redirect"]:
        return None
    if first["hash"] == second["hash"] or _similar_length(first["length"], second["length"]):
        return first
    return None


_baselines = {}


def soft404_baseline(target):
    """The site's not-found signature, computed once per target and shared
    across modules (sensitive files, readme version crawling)."""
    if target not in _baselines:
        _baselines[target] = _soft404_baseline(target)
    return _baselines[target]


def _looks_like_error_page(resp):
    """Cheap shape test: is this body plausibly an error/challenge page?

    HTML structure near the top, a very short body, or an error status all
    qualify. Plain-text bodies of real content (readmes, changelogs) do not,
    which is exactly what keeps their incidental marker words harmless.
    """
    if resp.status_code >= 400:
        return True
    body = resp.text or ""
    return (len(body) <= ERROR_SHAPE_MAX_BYTES
            or bool(ERROR_PAGE_SHAPE_RE.search(body[:MARKER_SCAN_BYTES])))


def response_is_junk(resp, target):
    """True when a 200 response is actually a not-found/challenge page.

    The site's soft-404 baseline is the primary signal and always applies.
    The error-marker scan only runs on error-shaped bodies (see
    _looks_like_error_page) so real readmes survive; WAF interstitials are
    HTML pages and never escape either check.
    """
    if resp is None:
        return True
    baseline = soft404_baseline(target)
    if baseline and _matches_baseline(resp, baseline):
        return True
    if _looks_like_error_page(resp) and \
            NOT_FOUND_MARKERS.search((resp.text or "")[:MARKER_SCAN_BYTES]):
        return True
    return False


def reset():
    """Clear the shared baseline cache (between scans/tests)."""
    _baselines.clear()


def _classify(path, resp, baseline, target):
    """Map one response to ('absent'|'protected'|'reachable'|'confirmed', detail)."""
    status = resp.status_code
    if status == 404:
        return "absent", ""
    if status // 100 == 3:
        location = resp.headers.get("Location", "")
        # a redirect to the site's own root/error page is how many WP setups
        # answer junk paths - not evidence the file exists
        if _redirects_into_site(location, target):
            return "absent", ""
        return "reachable", f"redirects to {location}"
    if status in (401, 403):
        return "protected", f"HTTP {status}"
    if status != 200:
        return "absent", ""

    body = resp.text or ""
    signature = CONTENT_SIGNATURES.get(path)
    if signature and re.search(signature[0], body, re.I):
        return "confirmed", signature[1]
    magic = MAGIC_SIGNATURES.get(path)
    if magic and (resp.content or b"").startswith(magic[0]):
        return "confirmed", magic[1]
    if NOT_FOUND_MARKERS.search(body[:MARKER_SCAN_BYTES]):
        return "absent", ""  # the body itself says "not found"/challenge
    if baseline and _matches_baseline(resp, baseline):
        return "absent", ""  # same as the site's not-found answer
    return "reachable", f"{len(resp.content)} bytes"


def _matches_baseline(resp, baseline):
    if resp.status_code != baseline["status"]:
        return False
    if _body_fingerprint(resp) == baseline["hash"]:
        return True
    return _similar_length(len(resp.content), baseline["length"])


def _redirects_into_site(location, target):
    if not location:
        return True  # no Location header at all - treat as unreachable answer
    host = urlsplit(location).hostname or urlsplit(target).hostname
    return host == (urlsplit(target).hostname or "")


def check_security_txt(report, target):
    """RFC 8615 security.txt - a positive finding only when actually published
    (its absence is the norm on WordPress sites, not worth a bullet).

    Checked at /.well-known/security.txt (canonical) and /security.txt
    (legacy placement); a 200 that is not a security.txt (soft-404, WAF
    challenge) is rejected via the shared junk checks.
    """
    for path in (".well-known/security.txt", "security.txt"):
        resp = httpclient.get(target + path, allow_redirects=False)
        if resp is None or resp.status_code != 200:
            continue
        body = resp.text or ""
        if "contact:" not in body.lower() or response_is_junk(resp, target):
            continue
        contacts = re.findall(r"(?im)^contact:\s*(\S+)", body)[:3]
        print(f"[*] security.txt published at /{path} (responsible disclosure contact)")
        report.paragraph(f"**security.txt** is published at `{path}` - the site offers "
                         f"a responsible-disclosure channel"
                         + (" (" + ", ".join(f"`{c}`" for c in contacts) + ")" if contacts else "")
                         + ". Good practice: it routes finders to the owner instead "
                           "of public disclosure.")
        return


def check_setup_wizard(report, target):
    """wp-admin/setup-config.php: the installation wizard must not be walkable
    on a deployed site (it can rewrite wp-config.php = full takeover).
    """
    resp = httpclient.get(f"{target}wp-admin/setup-config.php", allow_redirects=False)
    if resp is None or resp.status_code != 200:
        return
    body = resp.text or ""
    if "already exists" in body.lower():
        return  # installed site politely refusing - the normal, safe answer
    if re.search(r"name=[\"']dbname[\"']|setup-config\.php\?step=", body, re.I):
        print("[!] WordPress setup wizard reachable (wp-admin/setup-config.php)")
        report.paragraph("**Setup wizard reachable** at `wp-admin/setup-config.php` - the "
                         "installation/configuration step is still being served. On a "
                         "partially installed or misconfigured site this allows "
                         "re-running setup and overwriting wp-config.php (full site "
                         "takeover with reachable DB credentials). Verify it actually "
                         "progresses on this install.")


def check_directory_listing(report, target, slug, kind="plugins"):
    """Check whether wp-content/<kind>/<slug>/ has directory listing enabled."""
    url = f"{target}wp-content/{kind}/{slug}/"
    resp = httpclient.get(url)
    if resp is None or resp.status_code != 200:
        return False
    if LISTING_MARKER in resp.text:
        print(f"[!] Directory listing enabled: {url}")
        report.paragraph(f"Directory listing is **enabled** on {url} - the full source of this "
                         f"component (and any unprotected uploads inside it) is browsable.")
        return True
    return False
