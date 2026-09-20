"""Covert-traffic layer: make scanner requests look like ordinary browsing.

A WAF/blue team spots scripted scanners through a handful of signals. Each
persona + pacing feature below removes one of them:

- python's TLS ClientHello (JA3/JA4) screams "requests library" - fixed by
  the optional curl_cffi backend (impersonates a real browser's TLS + HTTP/2)
- HTTP/1.1-only connections (browsers negotiate HTTP/2) - also curl_cffi
- a bare 2-header request (UA + Accept-Encoding) - personas send the full,
  correctly-ordered header set a real browser sends
- a User-Agent that changes on every request - one persona is picked per scan
  and kept for its whole duration, exactly like a browser session
- no Referer on sub-page fetches - callers pass referer= for navigational
  requests, as a browser following a link would
- metronome-perfect request pacing - jitter adds uniformly random silence
- dictionary-order brute-force probing - see active/enumerate.py (shuffled)

This is opsec for AUTHORIZED engagements (and for testing a client's own
detection rules), not a cloaking device: volume and behaviour still matter
more than any header.
"""

import random

PERSONAS = {
    "chrome-win": {
        "impersonate": "chrome",
        "headers": [
            ("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,"
                       "image/avif,image/webp,image/apng,*/*;q=0.8"),
            ("Accept-Language", "en-US,en;q=0.9"),
            ("Upgrade-Insecure-Requests", "1"),
            ("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                           "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"),
            ("sec-ch-ua", '"Chromium";v="124", "Google Chrome";v="124", "Not-A.Brand";v="99"'),
            ("sec-ch-ua-mobile", "?0"),
            ("sec-ch-ua-platform", '"Windows"'),
            ("Sec-Fetch-Dest", "document"),
            ("Sec-Fetch-Mode", "navigate"),
            ("Sec-Fetch-Site", "none"),
            ("Sec-Fetch-User", "?1"),
        ],
    },
    "edge-win": {
        "impersonate": "edge",
        "headers": [
            ("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,"
                       "image/avif,image/webp,image/apng,*/*;q=0.8"),
            ("Accept-Language", "en-US,en;q=0.9"),
            ("Upgrade-Insecure-Requests", "1"),
            ("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                           "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0"),
            ("sec-ch-ua", '"Chromium";v="124", "Microsoft Edge";v="124", "Not-A.Brand";v="99"'),
            ("sec-ch-ua-mobile", "?0"),
            ("sec-ch-ua-platform", '"Windows"'),
            ("Sec-Fetch-Dest", "document"),
            ("Sec-Fetch-Mode", "navigate"),
            ("Sec-Fetch-Site", "none"),
            ("Sec-Fetch-User", "?1"),
        ],
    },
    "safari-mac": {
        "impersonate": "safari",
        "headers": [
            ("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"),
            ("Accept-Language", "en-US,en;q=0.9"),
            ("Upgrade-Insecure-Requests", "1"),
            ("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                           "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15"),
            ("Sec-Fetch-Dest", "document"),
            ("Sec-Fetch-Mode", "navigate"),
            ("Sec-Fetch-Site", "none"),
        ],
    },
    "firefox-linux": {
        "impersonate": "firefox",
        "headers": [
            ("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,"
                       "image/avif,image/webp,*/*;q=0.8"),
            ("Accept-Language", "en-US,en;q=0.5"),
            ("Upgrade-Insecure-Requests", "1"),
            ("User-Agent", "Mozilla/5.0 (X11; Linux x86_64; rv:133.0) Gecko/20100101 Firefox/133.0"),
            ("Sec-Fetch-Dest", "document"),
            ("Sec-Fetch-Mode", "navigate"),
            ("Sec-Fetch-Site", "none"),
            ("Sec-Fetch-User", "?1"),
        ],
    },
}


def pick_persona(name=None):
    """Return a persona dict; random browser per scan when no name is given."""
    if name:
        if name not in PERSONAS:
            raise ValueError(f"unknown persona '{name}' (choose from: {', '.join(PERSONAS)})")
        return {"name": name, **PERSONAS[name]}
    name = random.choice(list(PERSONAS))
    return {"name": name, **PERSONAS[name]}


def base_headers(persona):
    """Persona headers as an ordered dict (header order is itself a fingerprint)."""
    return {k: v for k, v in persona["headers"]}


def jittered_delay(base_delay, jitter):
    """base_delay + uniform random silence in [0, jitter]."""
    return max(0.0, base_delay) + (random.uniform(0, jitter) if jitter > 0 else 0.0)
