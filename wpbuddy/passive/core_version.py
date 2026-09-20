"""Passive WordPress core version discovery.

All plain GETs (stealthy), every method tried and EVERY hit collected (not
just the first) so the confidence layer can corroborate them:
1. <meta name="generator"> tag on the homepage
2. ?ver= parameter on core stylesheets (wp-block-library)
3. <generator> tag in the RSS feed
4. readme.html (classic information leak, still present on many installs)

Agreeing sources boost confidence; disagreeing ones (stale cache, fake
readme) surface as a discrepancy instead of silently winning by order.
"""

import re
from urllib.parse import parse_qs, urlparse

from bs4 import BeautifulSoup

from .. import httpclient
from ..versioning import extract_version

# Stylesheet ids that WordPress CORE enqueues (plugin stylesheet ?ver= values
# are the plugin's version, not core's, so only these are trustworthy).
CORE_CSS_IDS = {"wp-block-library-css", "wp-block-library-theme-css", "global-styles-css", "classic-theme-styles-css"}


def discover_core_version(target):
    """Collect (version, source_key, human_source) for every method that hits.

    Ordered by authoritativeness; never raises.
    """
    found = []
    resp = httpclient.get(target)
    if resp is not None:
        soup = BeautifulSoup(resp.text, "html.parser")
        version = _from_generator_meta(soup)
        if version:
            found.append((version, "meta-generator", "meta generator tag on the homepage"))
        version = _from_core_css(soup)
        if version:
            found.append((version, "core-css-ver", "?ver= parameter on a core stylesheet"))

    version = _from_feed(target)
    if version:
        found.append((version, "rss-generator", "RSS feed <generator> tag"))

    version = _from_readme_html(target)
    if version:
        found.append((version, "readme-html", "readme.html file"))

    return found


def _from_generator_meta(soup):
    tag = soup.find("meta", attrs={"name": "generator"})
    if tag is None:
        return None
    content = tag.get("content") or ""
    if "WordPress" not in content:
        return None
    return extract_version(content)


def _from_core_css(soup):
    for link in soup.find_all("link", href=True, id=True):
        if link["id"] not in CORE_CSS_IDS:
            continue
        ver = parse_qs(urlparse(link["href"]).query).get("ver", [""])[0]
        found = extract_version(ver)
        if found:
            return found
    return None


def _from_feed(target):
    resp = httpclient.get(f"{target}feed")
    if resp is None:
        return None
    match = re.search(r"<generator[^>]*>(.*?)</generator>", resp.text, re.S)
    return extract_version(match.group(1)) if match else None


def _from_readme_html(target):
    resp = httpclient.get(f"{target}readme.html")
    if resp is None or resp.status_code != 200:
        return None
    match = re.search(r"Version\s+(\d[\d.]*)", resp.text)
    return extract_version(match.group(1)) if match else None
