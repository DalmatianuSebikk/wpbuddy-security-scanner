"""Version crawling for discovered plugins and themes.

Reads the files plugins/themes still ship on most installs (readme.txt and
friends) and falls back to the standard `Version:` header of a theme's
style.css. The canonical WordPress readme.txt marker `Stable tag:` is tried
first - it is far more reliable than scraping the changelog.

False-positive control: a 200 answer proves nothing on hosts that soft-404
everything or sit behind a WAF challenge. Every fetched file is checked
against the site's shared not-found signature (files.soft404_baseline) and
against error/challenge markers BEFORE any version regex runs - a challenge
page must never yield a phantom version (and with it, phantom CVE matches).
"""

import re

from .. import obfuscate
from ..versioning import VERSION_RE, extract_version
from . import files

# Ordered by hit rate in the wild.
README_FILES = ("readme.txt", "README.txt", "readme.md", "README.md",
                "changelog.txt", "changes.txt", "release_log.html")

# Anchors after which a version number is most likely the component's own.
ANCHORS = ("stable tag", "changelog", "installation", "features", "version")

THEME_VERSION_RE = re.compile(r"^\s*Version:\s*(\d[\d.\w-]*)", re.I | re.M)

# Context that marks a number as the ENVIRONMENT's version, not the plugin's
# ("Requires PHP 7.4", "Tested up to WordPress 6.0") - once mis-read as the
# component's own version it produced wrong CVE matches.
_REQUIREMENT_CONTEXT_RE = re.compile(
    r"(requires?|needs?|compatible with|tested(?:\s+up\s+to)?|wordpress|php|wp)\s*"
    r"(?:(?:at least|up to|version)\s*)*:?\s*$", re.I)


def find_component_version(target, kind, slug):
    """Return (version or None, source file path or None, version_kind or None).

    `kind` is 'plugins' or 'themes'. version_kind ('stable-tag'/'style-css'/
    'changelog-anchor') tells the confidence layer how trustworthy the number is.
    """
    base = f"{target}wp-content/{kind}/{slug}/"

    for name in README_FILES:
        # WAFs (Wordfence et al.) commonly block plain readme probing - the
        # obfuscation fallback retries the same file through path variants
        resp, _ = obfuscate.fetch_first_allowed(base + name, referer=target)
        if resp is None or resp.status_code != 200:
            continue
        if files.response_is_junk(resp, target):
            continue  # soft-404 / WAF challenge page, not a readme
        version, method = _version_from_readme(resp.text)
        if version:
            return version, base + name, method

    if kind == "themes":
        resp, _ = obfuscate.fetch_first_allowed(base + "style.css", referer=target)
        if resp is not None and resp.status_code == 200 \
                and not files.response_is_junk(resp, target):
            match = THEME_VERSION_RE.search(resp.text)
            if match:
                return extract_version(match.group(1)), base + "style.css", "style-css"

    return None, None, None


def _version_from_readme(text):
    """Return (version or None, how_it_was_found).

    Methods, most trustworthy first:
    - 'stable-tag':   an explicit version statement in the first lines
                      ('Stable tag: X', 'version X' header, Divi's changelog head)
    - 'changelog-anchor': the first bare number after a changelog/features/
                      installation anchor - the fallback that can pick up a
                      wrong number, hence the low confidence weight
    """
    # Readmes and changelogs are NEWEST-FIRST: an explicit version statement in
    # the first lines is the shipped version. Everything below is history.
    head = text[:2000]
    head_match = re.search(
        r"(?im)^\s*(?:version|stable tag|v)\s*[:=]?\s*(\d+\.\d+(?:\.\d+)*)", head)
    if head_match:
        return head_match.group(1), "stable-tag"

    lowered = text.lower()
    for anchor in ANCHORS:
        idx = lowered.find(anchor)
        if idx == -1:
            continue
        # Look from the anchor onward, capped so we don't jump into next sections.
        window = lowered[idx:idx + 4000]
        for match in VERSION_RE.finditer(window):
            before = window[max(0, match.start() - 40):match.start()]
            if _REQUIREMENT_CONTEXT_RE.search(before):
                continue  # "Requires PHP 7.4" / "WordPress 6.0" is not our version
            return match.group(), "changelog-anchor"
    return None, None
