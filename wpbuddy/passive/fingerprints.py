"""Content-based plugin fingerprinting.

Catches plugins that are NOT visible in any URL - because the site uses a
CDN, minifies/renames asset paths, or simply prints plugin output into the
page. Each signature maps a plugin slug to places its presence leaks:

- html:     raw page markup (shortcodes, body classes, JS globals, cache
            plugin comments, data-attributes, wrapper div classes)
- cookies:  Set-Cookie name prefixes set by the plugin
- headers:  response header name prefixes
- rest:     REST namespace prefixes from /wp-json/ (e.g. 'wc/' -> wc/v3)

Every match is heuristic (a report says "fingerprint match"); the version
crawling + vulnerability matching that follow treat it like any other slug.
"""

import re

SIGNATURES = {
    "woocommerce": {"html": [r'class="[^"]*\bwoocommerce', r'woocommerce-MyAccount',
                             r'\[woocommerce_'], "cookies": ["woocommerce_"], "rest": ["wc/"]},
    "contact-form-7": {"html": [r'\[contact-form-7', r'\bwpcf7\b'], "rest": ["contact-form-7/"]},
    "wpforms-lite": {"html": [r'\[wpforms', r'wpforms-container']},
    "elementor": {"html": [r'data-elementor', r'elementor-kit-']},
    "wordpress-seo": {"html": [r'Yoast SEO plugin']},
    "seo-by-rank-math": {"html": [r'Rank Math SEO']},
    "all-in-one-seo-pack": {"html": [r'All in One SEO']},
    "jetpack": {"html": [r'jetpack-lazy', r'jp-carousel'], "rest": ["jetpack/"]},
    "wpdiscuz": {"html": [r'wpd-comment', r'\bwpdiscuz\b'], "rest": ["wpdiscuz/"]},
    "wordfence": {"cookies": ["wfvt_", "wordfence_"]},
    "all-in-one-wp-security-and-firewall": {"html": [r'aiowps']},
    "w3-total-cache": {"html": [r'W3 Total Cache']},
    "wp-super-cache": {"html": [r'WP Super Cache']},
    "litespeed-cache": {"html": [r'LiteSpeed Cache'], "headers": [("x-litespeed-cache", None)]},
    "autoptimize": {"html": [r'Autoptimize']},
    "sitepress-multilingual-cms": {"html": [r'\bwpml\b'], "cookies": ["_icl_"]},
    "nextgen-gallery": {"html": [r'\bngg-', r'\[ngg_images']},
    "gravityforms": {"html": [r'gform_wrapper', r'\[gravityform']},
    "ninja-forms": {"html": [r'nf-form', r'\[ninja_forms'], "rest": ["ninja-forms/"]},
    "buddypress": {"html": [r'\bbuddypress\b'], "rest": ["buddypress/"]},
    "bbpress": {"html": [r'\bbbpress\b', r'\bbbp-']},
    "duplicator": {"html": [r'\bduplicator\b', r'dup-installer']},
    "updraftplus": {"html": [r'updraftplus', r'updraft_']},
    "all-in-one-wp-migration": {"html": [r'\bai1wm\b', r'All-in-One WP Migration']},
    "memberpress": {"html": [r'\bmemberpress\b'], "rest": ["memberpress/"]},
}

_COMPILED = {slug: {k: ([re.compile(p, re.I) for p in v] if k == "html" else v)
                    for k, v in sigs.items()}
             for slug, sigs in SIGNATURES.items()}


def detect(artifacts, rest_namespaces):
    """Return the set of plugin slugs whose fingerprints appear in artifacts.

    artifacts: {'pages_html': str, 'cookies': set[str], 'headers': list[(name, value)]}
    rest_namespaces: non-core namespaces from /wp-json/ (may be None).
    """
    html = artifacts.get("pages_html", "")
    cookies = artifacts.get("cookies", set())
    headers = artifacts.get("headers", [])
    namespaces = rest_namespaces or []

    found = set()
    for slug, sigs in _COMPILED.items():
        if any(rx.search(html) for rx in sigs.get("html", [])):
            found.add(slug)
            continue
        if any(c.startswith(prefix) for c in cookies for prefix in sigs.get("cookies", [])):
            found.add(slug)
            continue
        if any(name.lower().startswith(hn.lower()) for name, _ in headers
               for hn, _ in sigs.get("headers", [])):
            found.add(slug)
            continue
        if any(ns.startswith(prefix) for ns in namespaces for prefix in sigs.get("rest", [])):
            found.add(slug)
    return found


def explain(slug):
    """Human-readable description of what matched categories exist for a slug."""
    sigs = SIGNATURES.get(slug, {})
    bits = [n for n in ("html", "cookies", "headers", "rest") if sigs.get(n)]
    return "+".join(bits)
