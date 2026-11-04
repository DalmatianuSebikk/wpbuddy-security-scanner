"""Content discovery for the `deep` profile (roadmap stage 1): mutation engine.

Wordlist-style backup hunting, calibrated against the site's soft-404
signature (a bare 200 means nothing on catch-all hosts) and executed by
the async worker pool with AIMD pacing - the roadmap's per-host
concurrency deliverable. GET-only; every request passes the engagement
gate (exclusions + budget).
"""

import asyncio
from urllib.parse import urljoin

from .. import config
from ..client import AIMDRate, AsyncClient
from . import files

# bases x suffixes: a compact, high-hit-rate grid instead of a full wordlist
BASES = ("wp-config.php", "wp-content/debug.log", "robots.txt", ".env",
         "backup", "db", "dump", "wp-config", "database")
SUFFIXES = ("", ".bak", ".old", ".txt", ".save", ".zip", ".tar.gz", ".sql", ".gz")
MAX_CANDIDATES = 250          # bounded by construction, budget-gated per request
CONCURRENCY = 6


def candidate_urls(target):
    """base x suffix grid (deduplicated) under the target root."""
    seen, out = set(), []
    for base in BASES:
        for suffix in SUFFIXES:
            path = base + suffix
            if path in seen:
                continue
            seen.add(path)
            out.append(urljoin(target, path))
    return out[:MAX_CANDIDATES]


def _interesting(url, resp, baseline, target):
    """(True, why) when a response is a real finding, not a soft-404."""
    if resp is None:
        return False, ""
    status = resp.status_code
    if status == 404:
        return False, ""
    if status in (401, 403):
        return True, f"protected (HTTP {status}) - may exist behind a rule"
    if status != 200:
        return False, ""
    body = resp.text or ""
    if "Index of /" in body:
        return True, "directory listing"
    if baseline and files._matches_baseline(resp, baseline):
        return False, ""
    if files.response_is_junk(resp, target):
        return False, ""
    magic = (resp.content or b"")[:4]
    if magic.startswith(b"PK\x03\x04"):
        return True, "ZIP archive"
    if "DB_PASSWORD" in body or ("define(" in body and "DB_" in body):
        return True, "configuration content"
    if "CREATE TABLE" in body or "INSERT INTO" in body:
        return True, "SQL dump content"
    return True, f"200 with {len(resp.content)} bytes"


def _engagement_gate(url):
    """Shared with httpclient: excluded paths + run budget (roadmap 2.3)."""
    engagement = getattr(config, "ENGAGEMENT", None)
    if engagement is not None and engagement.excludes(url):
        return f"path excluded by the engagement scope: {url}"
    budget = getattr(config, "RUN_BUDGET", None)
    if budget is not None and not budget.record_request():
        return budget.exceeded_reason
    return None


def run(report, target, emit=None, concurrency=CONCURRENCY):
    """Probes the mutation grid; findings land in a dedicated section."""
    baseline = files.soft404_baseline(target)   # calibrated once, budget-gated
    urls = candidate_urls(target)
    if emit is not None:
        emit("content-discovery-started", candidates=len(urls))

    client = AsyncClient(gate=_engagement_gate)

    async def scenario():
        rate = AIMDRate(min_delay=0.0, max_delay=5.0)
        try:
            return await client.fetch_many(urls, concurrency=concurrency, rate=rate)
        finally:
            await client.close()

    try:
        results = asyncio.run(scenario())
    except Exception as exc:
        report.paragraph(f"Deep content discovery failed ({exc}); continuing without it.")
        return []

    found = [(url, why) for url in urls
             for hit, why in [_interesting(url, results.get(url), baseline, target)] if hit]
    if emit is not None:
        emit("content-discovery-finished", found=len(found))

    report.section("Deep content discovery (deep profile)")
    if not found:
        report.paragraph(f"None of the {len(urls)} backup/mutation candidates "
                         "(wp-config copies, archives, dumps under common name/suffix "
                         "combinations) produced a real answer.")
        return found
    print(f"[!] Deep content discovery: {len(found)} hit(s)")
    report.paragraph(f"{len(found)} candidate path(s) produced real answers "
                     "(calibrated against this site's not-found signature):")
    report.bullets([f"`{url}` - {why}" for url, why in found])
    report.paragraph("**Recommendation:** backups, dumps and editor copies never belong "
                     "under the web root; delete them and block dotfiles at the server.")
    return found
