"""Dangling external references - the 'a 404 is a signal' lesson.

A page still linking to a host that no longer resolves anywhere is how
broken-link hijacking starts: an expired domain the site still trusts gets
registered by someone else, and whatever the site does with that host
(redirects, asset loads, mail links) now belongs to them. Detection is
passive and detection-only: external hostnames are harvested from the HTML
the crawl already collected and DNS-resolved; NXDOMAIN while still
referenced is a finding for the site owner. Proving an actual takeover
means registering the domain - that is engagement work a scanner must not do.
"""

import re
import socket
from urllib.parse import urlparse

HOST_RE = re.compile(r"(?:https?:)?//([A-Za-z0-9.-]+\.[A-Za-z]{2,})(?=[/\"'\s<>)]|$)")

# how many distinct external hosts to DNS-check (most-referenced first)
MAX_HOSTS = 40

# namespace/infra hosts nobody owns that appear in tons of pages
SKIP_HOSTS = {
    "www.w3.org", "w3.org", "schema.org", "purl.org", "gmpg.org",
    "wordpress.org", "s.w.org", "s0.wp.com", "s1.wp.com", "s2.wp.com",
}


def check(report, target, pages_html):
    """Report external hosts referenced by the crawled pages that no longer resolve."""
    from . import content  # reuse the same same-site rules as ref discovery

    target_host = (urlparse(target).hostname or "").lower()
    counts = {}
    for host in HOST_RE.findall(pages_html or ""):
        host = host.lower().strip(".")
        if not host or host in SKIP_HOSTS:
            continue
        if content._same_site(host, target_host):
            continue  # the site's own subdomains/CDN are its problem, not dangling
        counts[host] = counts.get(host, 0) + 1

    dangling = []
    for host in sorted(counts, key=counts.get, reverse=True)[:MAX_HOSTS]:
        if not _resolves(host):
            dangling.append((host, counts[host]))
    if not dangling:
        return

    print(f"[!] {len(dangling)} referenced external host(s) no longer resolve "
          "(possible broken-link hijacking)")
    report.section("Dangling external references")
    report.paragraph(
        "The site still references these external hosts, but their domains no "
        "longer resolve in DNS - the classic starting point of broken-link "
        "hijacking (someone registers the expired domain and inherits whatever "
        "trust the site places in it). Verify a domain is truly unregistered "
        "before claiming takeover; a local resolver outage looks the same.")
    report.bullets([f"**{host}** - referenced {count}x in the crawled pages, "
                    "does not resolve" for host, count in dangling])
    report.paragraph("**Recommendation:** remove or update dead references, and "
                     "keep DNS for every hostname the site links to or redirects "
                     "to under active ownership.")


def _resolves(host):
    try:
        socket.getaddrinfo(host, 80)
        return True
    except socket.gaierror:
        return False
