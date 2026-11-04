"""Aggressive discovery for the `deep` profile (roadmap stage 1).

Everything here is still GET-only and writes nothing - `deep` buys breadth
(recursive crawl, route inventory) at the cost of more requests, always
inside the engagement budget. The mutation-engine/content-discovery half
lives in contentdisc.py (async worker); this module is the sequential,
budget-gated crawler and the REST route inventory.
"""

import re
from urllib.parse import urljoin, urlsplit

from .. import httpclient
from .content import _same_site

MAX_LINKS_PER_PAGE = 25          # a nav menu can hold hundreds; cap the frontier
AJAX_ACTION_RE = re.compile(r"admin-ajax\.php\?action=([\w-]+)")
REST_ROUTE_JS_RE = re.compile(r"['\"]/?wp-json/([\w\-./%]+?)(?:\?|['\"])")


def deep_crawl(target, max_pages, pages_html_hook=None):
    """Recursive same-site crawl (BFS, page-capped).

    Seeded by the sitemap-aware page list (the same one the normal crawl
    uses) and then extended by following internal links - breadth without
    re-fetching what the passive phase already read. Returns
    (pages, forms, ajax_actions); forms is a list of {action, method,
    fields}, ajax_actions are admin-ajax action names mined from inline JS.
    """
    from bs4 import BeautifulSoup

    from . import content as content_mod

    host = (urlsplit(target).hostname or "").lower()
    seed = content_mod.crawl_page_urls(target, max_pages)
    seen, queue, pages = set(), list(dict.fromkeys(seed)), []
    forms, ajax_actions = [], set()

    while queue and len(pages) < max_pages:
        url = queue.pop(0)
        if url in seen:
            continue
        seen.add(url)
        resp = httpclient.get(url)
        if resp is None or resp.status_code != 200:
            continue
        pages.append(url)

        body = resp.text or ""
        if pages_html_hook:
            pages_html_hook(url, body)
        ajax_actions.update(AJAX_ACTION_RE.findall(body))

        soup = BeautifulSoup(body, "html.parser")
        for form in soup.find_all("form"):
            fields = sorted({i.get("name") for i in form.find_all(["input", "textarea", "select"])
                             if i.get("name")})
            forms.append({"action": urljoin(url, form.get("action") or url),
                          "method": (form.get("method") or "GET").upper(),
                          "fields": fields})
        added = 0
        for link in soup.find_all("a", href=True):
            candidate = urljoin(url, link["href"].split("#")[0])
            if candidate in seen or not _same_site((urlsplit(candidate).hostname or "").lower(),
                                                   host):
                continue
            if any(candidate.startswith(p) for p in (".jpg", ".png", ".pdf")):
                continue
            queue.append(candidate)
            added += 1
            if added >= MAX_LINKS_PER_PAGE or len(queue) + len(pages) >= max_pages * 2:
                break

    return pages, forms, sorted(ajax_actions)


def route_inventory(report, target, max_options=25):
    """REST route inventory from /wp-json/ plus per-route OPTIONS (deep).

    The index already lists routes and their methods for authenticated
    users; OPTIONS verifies what an anonymous client is actually allowed
    to call - the auth matrix the roadmap asks the deep profile to record.
    """
    resp = httpclient.get(f"{target}wp-json/")
    if resp is None or resp.status_code != 200:
        report.paragraph("Route inventory skipped: /wp-json/ is not readable.")
        return None
    try:
        payload = resp.json()
    except (ValueError, AttributeError):
        report.paragraph("Route inventory skipped: /wp-json/ did not return JSON.")
        return None
    routes = payload.get("routes") or {}
    if not isinstance(routes, dict) or not routes:
        report.paragraph("The REST index exposes no route table (disabled or filtered).")
        return None

    inventory = {}
    for path, spec in sorted(routes.items()):
        methods = sorted(spec.get("methods") or []) if isinstance(spec, dict) else []
        inventory[path] = {"methods": methods, "auth": (spec or {}).get("auth")}

    # OPTIONS per route, bounded: anonymous method surface + confirmation
    probed = 0
    for path, entry in inventory.items():
        if probed >= max_options:
            break
        if path == "/" or not entry["methods"]:
            continue
        probed += 1
        options = httpclient.request("OPTIONS", f"{target}wp-json/{path.lstrip('/')}",
                                     retries=1)
        if options is None or options.status_code >= 400:
            entry["anon_methods"] = []
            continue
        allow = options.headers.get("Allow", "")
        entry["anon_methods"] = [m.strip().upper() for m in allow.split(",") if m.strip()]

    report.section("REST route inventory (deep)")
    writable = [p for p, e in inventory.items()
                if set(e.get("anon_methods") or ()) & {"POST", "PUT", "PATCH", "DELETE"}]
    report.paragraph(f"{len(inventory)} route(s) in the REST index"
                     + (f"; {probed} probed with OPTIONS" if probed else "")
                     + ". Routes an ANONYMOUS visitor may write to are listed first - "
                       "each is a plugin-provided surface worth auditing:")
    if writable:
        write_methods = {"POST", "PUT", "PATCH", "DELETE"}
        report.bullets([
            f"`{path}` - anonymous "
            + ", ".join(m for m in (inventory[path].get("anon_methods") or [])
                        if m in write_methods)
            for path in writable])
    else:
        report.paragraph("No route answered OPTIONS with write methods for anonymous "
                         "callers (read surface only).")
    methods_line = ", ".join(
        f"`{path}` ({'/'.join(e.get('anon_methods') or e['methods'] or ['?'])})"
        for path, e in sorted(inventory.items())[:40])
    report.paragraph("Method surface: " + methods_line + ".")
    return inventory


def run(report, target, args, emit=None):
    """The deep-discovery phase handler: crawl + route inventory.

    The recursive crawl replaces nothing - the normal passive crawl still
    runs; this adds breadth and the JS/form mining on top.
    """
    pages, forms, ajax_actions = deep_crawl(target, max_pages=getattr(args, "max_pages", 5))
    if emit is not None:
        emit("deep-crawl-finished", pages=len(pages), forms=len(forms),
             ajax_actions=len(ajax_actions))
    print(f"[*] Deep crawl: {len(pages)} page(s), {len(forms)} form(s), "
          f"{len(ajax_actions)} admin-ajax action(s) mined from JS")

    if ajax_actions:
        report.section("admin-ajax actions mined from page sources (deep)")
        report.paragraph("Actions referenced by the site's own JavaScript - each is a "
                         "registered AJAX handler (check which are `wp_ajax_nopriv_*` in "
                         "the audited plugin code): "
                         + ", ".join(f"`{a}`" for a in ajax_actions))
    if forms:
        report.section("Form surface (deep)")
        report.paragraph("Every form the crawl saw, with its parameters - the natural "
                         "input list for later parameter-level work:")
        report.bullets([f"`{f['method']} {f['action']}` - fields: "
                        + ", ".join(f"`{name}`" for name in f["fields"])
                        for f in forms[:20]])

    return route_inventory(report, target)
