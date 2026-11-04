"""Plugin slug enumeration by brute force (invasive - opt-in via --enum-plugins).

The fallback when a plugin leaves no trace in pages at all: probe
/wp-content/plugins/<slug>/readme.txt for every slug from the wordpress.org
"popular" ranking (fetched live from the official plugins API, so the list
never goes stale like a shipped wordlist). 200 = plugin installed; 403 counts
only when the server does not blanket-deny the whole path class (checked
up front with one bogus-slug probe).

This generates one request per slug - it is deliberately NOT part of the
default scan.
"""

import random

from .. import httpclient, obfuscate
from ..passive import files  # no cycle: passive never imports active at module level

WORDPRESS_ORG_API = "https://api.wordpress.org/plugins/info/1.2/"


def fetch_popular_slugs(limit):
    """Live 'popular' plugin slugs from the official wordpress.org API."""
    slugs, page = [], 1
    while len(slugs) < limit:
        resp = httpclient.get_json(
            WORDPRESS_ORG_API,
            params={"action": "query_plugins",
                    "request[per_page]": 100,
                    "request[browse]": "popular",
                    "request[page]": page},
            retries=1,
        )
        if not isinstance(resp, dict) or not resp.get("plugins"):
            break
        slugs += [p["slug"] for p in resp["plugins"] if isinstance(p, dict) and p.get("slug")]
        if len(resp["plugins"]) < 100:
            break
        page += 1
    return slugs[:limit]


def _blanket_deny(target):
    """True when the server denies the whole plugins-readme path class.

    One probe with an obviously bogus slug (the files.py blanket-rule pattern):
    if even that gets 401/403, a 403 on a real slug is a firewall rule, not a
    protected file - and must not be read as "plugin installed".
    """
    bogus = f"wpbuddy-{random.randrange(1 << 30):x}"
    resp = httpclient.get(f"{target}wp-content/plugins/{bogus}/readme.txt",
                          retries=1, allow_redirects=False)
    return resp is not None and resp.status_code in (401, 403)


def probe_slug(target, slug, strict_200=False):
    """True when /wp-content/plugins/<slug>/readme.txt proves the plugin exists.

    A 200 only counts when the body is NOT junk: WAFs serve their challenge
    interstitials with HTTP 200, and catch-all rewrites answer every path
    with a soft-404 page - either one used to "install" every probed slug
    (P1-2). A 403 counts only while the server is known NOT to blanket-deny
    this path class (strict_200=False): with a blanket rule in place, 403
    answers every slug and says nothing about existence.
    """
    resp, _ = obfuscate.fetch_first_allowed(
        f"{target}wp-content/plugins/{slug}/readme.txt", retries=1)
    if resp is None:
        return False
    if resp.status_code == 200:
        return not files.response_is_junk(resp, target)
    return resp.status_code == 403 and not strict_200


def enumerate_plugins(report, target, slugs):
    """Probe each slug; returns the installed ones. Reports progress inline.

    Slugs are shuffled: probing a dictionary in sorted order is itself a
    scan signature, and shuffling costs nothing.
    """
    slugs = list(slugs)
    random.shuffle(slugs)

    report.section("Plugin slug enumeration (invasive)")
    report.paragraph(f"Brute-forcing {len(slugs)} popular plugin slugs against "
                     f"`wp-content/plugins/<slug>/readme.txt` (one request per slug, "
                     "enabled by --enum-plugins). An answer counts only when its content "
                     "is a real response - WAF challenge pages and soft-404 catch-alls "
                     "arrive as HTTP 200 too and are rejected.")

    deny_is_noise = _blanket_deny(target)
    if deny_is_noise:
        print("[*] Server denies the plugins-readme path class wholesale "
              "(bogus slug got 401/403) - only real 200 answers count as installed")
        report.paragraph("An obviously bogus plugin slug was denied the same way as real "
                         "ones, so the 401/403s here are a blanket firewall rule, **not** "
                         "evidence that a plugin exists. Only answers whose content actually "
                         "came back (HTTP 200, some via path obfuscation) are counted.")

    # learn the site's junk/soft-404 signature ONCE before the loop (cached
    # either way, but front-loading keeps the two baseline probes out of the
    # per-slug request stream)
    files.soft404_baseline(target)

    installed = []
    for done, slug in enumerate(slugs, 1):
        if probe_slug(target, slug, strict_200=deny_is_noise):
            installed.append(slug)
            print(f"[!] Enum: plugin installed: {slug}")
        if done % 50 == 0:
            print(f"[*] Enum progress: {done}/{len(slugs)} slugs probed")

    if installed:
        report.paragraph("Plugins confirmed present by enumeration "
                         "(invisible in page sources):")
        report.bullets([f"**{s}**" for s in installed])
    else:
        report.paragraph("Enumeration found no additional plugins.")
    return installed
