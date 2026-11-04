"""Path-obfuscation fallback for WAF-blocked probes.

When a plain request is blocked (403/406/429/501), retry through a ladder of
standard normalization-based variants - the same family of techniques a
sqlmap/Burp operator uses (path pollution, self-referencing segments,
percent-encoding, case variation, segment parameters). Variants are tried
ONLY after the plain request was blocked, so an unfiltered target pays zero
extra requests. Disable everything with --no-evade.

These work because many WAFs match the *literal* request path while the
origin server normalizes it back to the same resource.
"""

from urllib.parse import urlsplit, urlunsplit

from . import config, httpclient, waf


def path_variants(path):
    """Obfuscated forms of a URL path, cheapest/most-compatible first."""
    variants = []
    if path.startswith("/"):
        # self-referencing segment: /./wp-content/...
        variants.append(("dot-segment", "/." + path))
        # double slash: //wp-content/...
        variants.append(("double-slash", "/" + path))
        first, _, rest = path[1:].partition("/")
        # segment parameter: /wp-content;/plugins/... (parsers drop ';...')
        variants.append(("semicolon-segment", f"/{first};/{rest}" if rest else path))
    # percent-encode inner slashes (origin usually decodes before routing)
    variants.append(("percent-slash", "/" + path[1:].replace("/", "%2f")))
    # case variation (origin filesystems are often case-insensitive)
    variants.append(("case-flip", _case_flip(path)))
    return [(tech, v) for tech, v in variants if v and v != path]


def _case_flip(path):
    parts = path.split("/")
    flipped = []
    for index, part in enumerate(parts):
        if part and index < 3:  # wp-content / plugins|themes segments
            flipped.append(part[0].upper() + part[1:])
        else:
            flipped.append(part)
    return "/".join(flipped)


def fetch_first_allowed(url, **kwargs):
    """GET a URL plainly; if a firewall blocks it, retry obfuscated variants.

    Returns (response_or_None, technique_used_or_None).
    """
    resp = httpclient.get(url, **kwargs)
    if resp is not None and not waf.is_blocked(resp):
        return resp, None
    if resp is not None:
        waf.note_block()

    if not getattr(config, "EVADE", True):
        return resp, None

    parts = urlsplit(url)
    for technique, variant in path_variants(parts.path):
        variant_url = urlunsplit((parts.scheme, parts.netloc, variant, parts.query, ""))
        vresp = httpclient.get(variant_url, **kwargs)
        if vresp is not None and not waf.is_blocked(vresp):
            if vresp.status_code < 400:
                # only a REAL answer counts as a bypass for the report. A 404/5xx
                # through the variant is still returned as data (the file is
                # absent), but a firewall that answered with an error page did
                # not get "beaten" - recording it inflated the bypass stats.
                waf.note_bypass(technique)
            return vresp, technique
    return resp, None
