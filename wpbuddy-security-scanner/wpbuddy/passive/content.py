"""Plugin and theme discovery from the target's own HTML.

False-positive control is the name of the game here: a `wp-content/plugins/`
string anywhere in raw page text proves nothing (articles quote plugin paths,
code blocks contain them, links point at OTHER WordPress sites). So discovery
only trusts two places:

1. resource-tag attributes (link/script/img/a/iframe/srcset/...) - real
   references the page's own markup loads or links to
2. inline <script> bodies - JS building plugin URLs at runtime

and only keeps matches that point at the TARGET: relative/protocol-relative
URLs, absolute URLs on the same host, or same base-domain hosts (a site's own
CDN like static.example.com). An absolute URL to a different registrable
domain (someone else's blog) is dropped - it says nothing about this site.

Findings are still leads: a same-site reference from article content is
possible, which is why the scan report separates version-confirmed plugins
from unverified references, and why `--enum-plugins` exists as proof.
"""

import re
from urllib.parse import urljoin, urlparse

from .. import httpclient

PATH_RE = re.compile(r"wp-content/(plugins|themes)/([A-Za-z0-9_][A-Za-z0-9_.\-]*)/", re.I)

# scheme://host immediately preceding a match (absolute or protocol-relative URL)
HOST_PREFIX_RE = re.compile(r"(?:https?:)?//([^/\s'\"<>]+)$", re.I)

RESOURCE_ATTRS = ("href", "src", "data-src", "poster", "srcset")

SITEMAP_PATHS = ("wp-sitemap.xml", "sitemap_index.xml", "sitemap.xml")

LOC_RE = re.compile(r"<loc>\s*(.*?)\s*</loc>", re.I)


def crawl_page_urls(target, max_pages):
    """Collect internal page URLs: the homepage first, then sitemap entries.

    Follows sitemap indexes (wp-sitemap.xml / Yoast sitemap_index.xml) one or
    two levels deep. Only same-host URLs are kept so a poisoned sitemap can't
    make the scanner crawl third-party sites.
    """
    urls = [target]
    host = urlparse(target).hostname

    for path in SITEMAP_PATHS:
        index_url = urljoin(target, path)
        resp = httpclient.get(index_url)
        if resp is None or resp.status_code != 200 or "<loc>" not in resp.text:
            continue
        _collect_sitemap_urls(index_url, resp.text, host, urls, max_pages, set())
        break  # first sitemap format that works is enough

    if len(urls) > 1:
        print(f"[*] Sitemap found; crawling up to {max_pages} pages for references")
    return urls[:max_pages]


def _collect_sitemap_urls(url, xml, host, urls, max_pages, seen, depth=0):
    if url in seen or depth > 2 or len(urls) >= max_pages:
        return
    seen.add(url)
    for loc in LOC_RE.findall(xml):
        loc = loc.strip()
        if urlparse(loc).hostname != host:
            continue
        if loc.endswith(".xml"):  # nested sitemap (sitemap of sitemaps)
            resp = httpclient.get(loc)
            if resp is not None and resp.status_code == 200 and "<loc>" in resp.text:
                _collect_sitemap_urls(loc, resp.text, host, urls, max_pages, seen, depth + 1)
        elif loc not in urls:
            urls.append(loc)
            if len(urls) >= max_pages:
                return


def discover_refs(page_urls, target):
    """Fetch each page; harvest plugin/theme slugs plus fingerprint artifacts.

    Returns (refs, artifacts):
      refs      {'plugins': set, 'themes': set} - same-site references only
      artifacts {'pages_html': str, 'cookies': set, 'headers': [(name, value)]}
    """
    from bs4 import BeautifulSoup

    refs = {"plugins": set(), "themes": set()}
    artifacts = {"pages_html": "", "cookies": set(), "headers": []}
    target_host = (urlparse(target).hostname or "").lower()
    referer = None  # browsers send the previous page as Referer when following links

    for url in page_urls:
        resp = httpclient.get(url, referer=referer)
        referer = url
        if resp is None:
            continue
        artifacts["pages_html"] += resp.text + "\n"
        artifacts["cookies"].update(resp.cookies.keys())
        artifacts["headers"] += list(resp.headers.items())

        soup = BeautifulSoup(resp.text, "html.parser")
        candidates = []
        for tag in soup.find_all(["link", "script", "img", "a", "iframe", "embed", "object", "source", "video", "audio"]):
            for attr in RESOURCE_ATTRS:
                value = tag.get(attr)
                if value:
                    candidates.append(value)
        for script in soup.find_all("script"):
            if not script.get("src") and len(script.get_text() or "") > 5:
                candidates.append(script.get_text())

        for candidate in candidates:
            for match in PATH_RE.finditer(candidate):
                kind, slug = match.group(1).lower(), match.group(2).rstrip(".")
                ref_host = _host_prefix(candidate, match.start())
                if _same_site(ref_host, target_host):
                    refs[f"{kind}"].add(slug)
    return refs, artifacts


def _host_prefix(candidate, match_start):
    """Host of an absolute/protocol-relative URL immediately before a match, else None."""
    prefix = candidate[:match_start].rstrip("/ ")  # drop the / separator before the path
    m = HOST_PREFIX_RE.search(prefix)
    if not m:
        return None
    return m.group(1).lower().split(":")[0]  # drop :port


# Multi-part public suffixes where the registrable domain is the LAST THREE
# labels. Without this set, _base_domain("x.co.uk") == "co.uk" - and every
# *.co.uk site on the internet would count as "same site" as the target
# (a blog article linking to another .co.uk WordPress install would then
# report that install's plugins as the target's).
_MULTIPART_SUFFIXES = {
    "co.uk", "org.uk", "gov.uk", "ac.uk", "me.uk",
    "com.au", "net.au", "org.au", "gov.au", "edu.au",
    "co.nz", "net.nz", "org.nz", "govt.nz",
    "co.jp", "ne.jp", "or.jp", "ac.jp",
    "com.br", "com.mx", "com.ar", "com.co",
    "co.za", "com.sg", "com.hk", "com.tw", "com.cn",
    "com.tr", "co.in", "co.ke",
}


def _base_domain(host):
    parts = host.lower().split(".")
    if len(parts) >= 3 and ".".join(parts[-2:]) in _MULTIPART_SUFFIXES:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def _same_site(ref_host, target_host):
    """True for relative URLs (no host), the target host, or its own subdomains/CDN."""
    if not ref_host:
        return True
    if ref_host == target_host:
        return True
    if not target_host:
        return False
    return (_base_domain(ref_host) == _base_domain(target_host)
            or ref_host.endswith("." + _base_domain(target_host)))
