"""Component versions from static-asset ?ver= parameters (F-5).

WordPress enqueues plugin/theme CSS+JS with the component's own version as
the cache-busting parameter (`...styles.css?ver=5.3.1`). When readme.txt is
unreadable (blocked, removed, soft-404'd) that parameter is often the only
passive version signal left - and it is a good one: the value comes from the
plugin's own code at enqueue time.

Same-site filtering matches the reference discovery rules: an article
embedding another WordPress site's assets must not pin a version onto this
target's component of the same name.
"""

import re

ASSET_VER_RE = re.compile(
    r"wp-content/(plugins|themes)/([A-Za-z0-9_][A-Za-z0-9_.\-]+)/"
    r"[^?\"'\s>]*[?&]ver=(\d+(?:\.\d+){1,3})", re.I)


def asset_versions(pages_html, target_host):
    """{(kind, slug): version} - the most frequent ?ver= per component.

    Disagreements (stale cached pages next to current ones) resolve to the
    majority value; a single stray number cannot win against several
    agreeing assets.
    """
    from .content import _host_prefix, _same_site
    counts = {}
    for match in ASSET_VER_RE.finditer(pages_html or ""):
        kind = match.group(1).lower()
        slug = match.group(2).rstrip(".")
        version = match.group(3)
        host = _host_prefix(pages_html, match.start())
        if not _same_site(host, (target_host or "").lower()):
            continue
        per_version = counts.setdefault((kind, slug), {})
        per_version[version] = per_version.get(version, 0) + 1
    return {key: max(versions, key=versions.get)
            for key, versions in counts.items()}
