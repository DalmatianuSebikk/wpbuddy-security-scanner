"""Single HTTP entry point for the whole scanner.

Every module must go through request()/get()/post() so that timeouts,
browser personas, the covert backend (curl_cffi TLS/HTTP2 impersonation),
the politeness delay and the retry policy are applied consistently.

init_networking() configures the layer once per scan (persona, proxy,
impersonation); without it a random persona on the plain `requests` backend
is used. request() never raises for network problems: it returns the final
Response, or None when every attempt failed, so callers degrade gracefully.
"""

import time

import requests

from . import config, stealth

SESSION = None
_consecutive_failures = 0

# After this many consecutive network-level failures, later requests get a
# single attempt each until a response gets through again (a dead or blocking
# target must not cost 3 attempts x retry-delay per remaining probe).
CONSECUTIVE_FAILURE_LIMIT = 5

# A 429 means "you are too fast", not "this path is forbidden": path evasion
# would make it worse. Instead every 429 arms a scan-wide cool-down that
# escalates (5s, 10s, 20s... capped) until any non-429 response resets it.
# A server-provided Retry-After is honoured when present.
RATE_LIMIT_MIN_BACKOFF = 5.0
RATE_LIMIT_MAX_BACKOFF = 60.0
_rate_limit_backoff = 0.0


def _note_rate_limited(resp):
    """Escalate the global cool-down after a 429 (honours Retry-After)."""
    global _rate_limit_backoff
    retry_after = 0.0
    try:
        retry_after = min(max(float(resp.headers.get("Retry-After") or 0), 0.0), 120.0)
    except (ValueError, TypeError, AttributeError):
        pass
    _rate_limit_backoff = min(max(_rate_limit_backoff * 2, RATE_LIMIT_MIN_BACKOFF, retry_after),
                              RATE_LIMIT_MAX_BACKOFF)
    print(f"[*] Rate-limited (429) by the target; backing off "
          f"{_rate_limit_backoff:.0f}s before further requests")


def init_networking(persona=None, proxy=None, impersonate=False):
    """(Re)build the session: persona headers, optional curl_cffi backend, proxy."""
    global SESSION
    config.PERSONA = stealth.pick_persona(persona)
    config.HTTP_BACKEND = "requests"
    SESSION = requests.Session()

    if impersonate:
        try:
            from curl_cffi.requests import Session as CffiSession
        except ImportError:
            print("[!] --covert: curl_cffi is not installed, staying on plain requests "
                  "(python TLS fingerprint - install with: uv pip install '.[covert]')")
        else:
            try:
                SESSION = CffiSession(impersonate=config.PERSONA["impersonate"])
                config.HTTP_BACKEND = "curl_cffi"
                print(f"[*] Covert networking: impersonating "
                      f"{config.PERSONA['name']} TLS/HTTP2 profile via curl_cffi")
            except Exception as e:  # unsupported impersonate target etc.
                print(f"[!] curl_cffi init failed ({e}); staying on plain requests")

    if proxy:
        SESSION.proxies = {"http": proxy, "https": proxy}
        print(f"[*] Routing all traffic through proxy {proxy}")


def _auth_headers(url):
    """Operator credentials (--cookie / --app-password, F-3) for the target
    host ONLY: the same HTTP layer also talks to wpvulnerability.net, NVD
    and wordpress.org, and site credentials must never leak there."""
    from urllib.parse import urlsplit
    if not config.TARGET_HOST:
        return {}
    host = (urlsplit(url).hostname or "").lower()
    if host != config.TARGET_HOST:
        return {}
    headers = {}
    if config.AUTH_COOKIE:
        headers["Cookie"] = config.AUTH_COOKIE
    if config.AUTH_BASIC:
        headers["Authorization"] = f"Basic {config.AUTH_BASIC}"
    return headers


def request(method, url, *, timeout=None, retries=config.DEFAULT_RETRIES,
            retry_delay=config.RETRY_DELAY, referer=None, **kwargs):
    """Send an HTTP request with retries on connection-level failures.

    A 5xx answer is the server's definitive response, not a transient hiccup,
    so it is returned immediately without retrying (retrying 500s inside scan
    loops used to produce long retry storms against WAF'd endpoints).
    Retries (with backoff) apply to connection errors, timeouts, DNS and TLS
    failures only. A 429 is never answered with more probes: it arms the
    scan-wide cool-down above, so being rate-limited makes the scanner
    quieter, not louder. Returns the Response (even 4xx/5xx), or None if every
    attempt raised a network error.
    """
    if SESSION is None:
        init_networking()
    timeout = config.DEFAULT_TIMEOUT if timeout is None else timeout
    extra_headers = dict(kwargs.pop("headers", None) or {})

    global _consecutive_failures, _rate_limit_backoff
    if _consecutive_failures >= CONSECUTIVE_FAILURE_LIMIT:
        retries = 1  # single-shot until a response gets through again
    if _rate_limit_backoff > 0:
        time.sleep(_rate_limit_backoff)  # cool down from an earlier 429

    last_error = None
    for attempt in range(retries):
        try:
            headers = stealth.base_headers(config.PERSONA or stealth.pick_persona())
            if referer:
                headers["Referer"] = referer
                headers["Sec-Fetch-Site"] = "same-origin"
            headers.update(extra_headers)
            headers.update(_auth_headers(url))
            resp = SESSION.request(method, url, timeout=timeout, headers=headers, **kwargs)
            if resp.status_code == 429:
                _note_rate_limited(resp)
                if attempt < retries - 1:
                    time.sleep(retry_delay)
                    continue
            else:
                _rate_limit_backoff = 0.0
            _consecutive_failures = 0
            _polite_pause()
            inspect_response(resp)
            return resp
        except Exception as e:  # connection errors, timeouts, DNS, TLS...
            last_error = e
        if attempt < retries - 1:
            print(f"[*] Request to {url} failed ({last_error}); retrying in {retry_delay}s "
                  f"({attempt + 1}/{retries})")
            time.sleep(retry_delay)

    _consecutive_failures += 1
    if _consecutive_failures == CONSECUTIVE_FAILURE_LIMIT:
        print(f"[!] {CONSECUTIVE_FAILURE_LIMIT} consecutive requests failed at network level - "
              "the target or your connection may be down; continuing with single attempts")
    print(f"[!] Giving up on {url} after {retries} attempts ({last_error})")
    return None


_inspect_warned = False


def inspect_response(resp):
    """Feed a response to the passive collectors (error pages, WAF).

    Deliberately never raises: a bug in an inspector must degrade to 'no
    analysis', never masquerade as a network failure inside the retry loop.
    """
    global _inspect_warned
    try:
        from . import waf
        from .passive import errorpages  # deferred: avoids import cycles at load time
        errorpages.inspect(resp)
        waf.inspect_response(resp)
    except Exception as e:
        if not _inspect_warned:
            _inspect_warned = True
            print(f"[!] Response analysis disabled by an internal error: {e!r}")


def get(url, **kwargs):
    kwargs.setdefault("allow_redirects", True)
    return request("GET", url, **kwargs)


def post(url, **kwargs):
    kwargs.setdefault("allow_redirects", True)
    return request("POST", url, **kwargs)


def get_json(url, **kwargs):
    """GET a URL and parse JSON; returns None on network failure or non-JSON body."""
    resp = get(url, **kwargs)
    if resp is None:
        return None
    try:
        return resp.json()
    except ValueError:
        return None


def _polite_pause():
    delay = stealth.jittered_delay(config.REQUEST_DELAY, config.REQUEST_JITTER)
    if delay > 0:
        time.sleep(delay)
