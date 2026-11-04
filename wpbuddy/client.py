"""Injectable HTTP clients: one interface, sync and async backends (roadmap 2.4).

The global httpclient singleton stays as the default transport for the
existing phases (swapping it everywhere at once would churn every module);
NEW consumers - the aggressive-discovery worker (stage 1) and the exploit
runner (stage 2) - take a client INSTANCE instead, each with its own
session, persona and retry policy. That is the injectability the
roadmap asks for: per-target, per-session, no shared globals.

Backends: `requests` (or curl_cffi impersonation) for the sync client;
`curl_cffi.requests.AsyncSession` or `httpx` for the async client - both
optional, discovered at construction, never a hard runtime dependency.
"""

from __future__ import annotations

import asyncio
import time
from urllib.parse import urlsplit

from . import config, stealth


class BackendUnavailable(RuntimeError):
    """No async backend installed (curl_cffi or httpx)."""


class SyncClient:
    """A self-contained synchronous client (one target/session).

    Owns its session and settings; nothing global is read at call time
    except config timeouts. Mirrors httpclient's call surface so callers
    can move between them unchanged.
    """

    def __init__(self, persona=None, proxy=None, impersonate=False, timeout=None):
        self.timeout = timeout or config.DEFAULT_TIMEOUT
        self.persona = stealth.pick_persona(persona)
        self.proxy = proxy
        self._session = None
        self._impersonate = impersonate
        self._impersonated = False

    def _ensure_session(self):
        if self._session is not None:
            return self._session
        if self._impersonate:
            try:
                from curl_cffi.requests import Session as CffiSession
            except ImportError:
                print("[!] client: curl_cffi not installed; using plain requests")
            else:
                self._session = CffiSession(impersonate=self.persona["impersonate"])
                self._impersonated = True
        if self._session is None:
            import requests
            self._session = requests.Session()
        if self.proxy:
            self._session.proxies = {"http": self.proxy, "https": self.proxy}
        return self._session

    def request(self, method, url, retries=1, retry_delay=1.0, headers=None, **kwargs):
        """Send with retries on transport errors; returns the Response or None."""
        merged = stealth.base_headers(self.persona)
        merged.update(headers or {})
        last_error = None
        for attempt in range(retries):
            try:
                resp = self._ensure_session().request(
                    method, url, timeout=self.timeout, headers=merged, **kwargs)
                self._polite_pause()
                return resp
            except Exception as exc:  # transport-level failures only
                last_error = exc
            if attempt < retries - 1:
                time.sleep(retry_delay)
        print(f"[!] client: giving up on {url} ({last_error})")
        return None

    def get(self, url, **kwargs):
        kwargs.setdefault("allow_redirects", True)
        return self.request("GET", url, **kwargs)

    def post(self, url, **kwargs):
        kwargs.setdefault("allow_redirects", True)
        return self.request("POST", url, **kwargs)

    def close(self):
        if self._session is not None:
            try:
                self._session.close()
            except Exception:
                pass
            self._session = None

    def _polite_pause(self):
        delay = stealth.jittered_delay(config.REQUEST_DELAY, config.REQUEST_JITTER)
        if delay > 0:
            time.sleep(delay)


class AsyncClient:
    """The async face of the same interface (roadmap 2.4).

    Backend discovery happens once, at construction: curl_cffi's
    AsyncSession (supports the same browser impersonation as the sync
    path) or httpx. Neither installed -> BackendUnavailable, never a
    silent fallback to something slower.
    """

    def __init__(self, persona=None, impersonate=False, timeout=None, gate=None):
        self.timeout = timeout or config.DEFAULT_TIMEOUT
        self.persona = stealth.pick_persona(persona)
        self.headers = stealth.base_headers(self.persona)
        self._impersonate = impersonate
        self._backend = None
        self._kind = None
        self._gate_warned = False
        # optional pre-send gate (engagement budget/exclusions, roadmap 2.3):
        # returns None to allow, or a reason string to block the request
        self.gate = gate

    def _ensure_backend(self):
        if self._kind is not None:
            return
        if self._impersonate:
            try:
                from curl_cffi.requests import AsyncSession
                self._backend = AsyncSession(impersonate=self.persona["impersonate"])
                self._kind = "curl_cffi"
                return
            except ImportError:
                pass
        try:
            import httpx
            self._backend = httpx.AsyncClient(timeout=self.timeout,
                                              headers=self.headers, follow_redirects=True)
            self._kind = "httpx"
            return
        except ImportError:
            pass
        try:
            from curl_cffi.requests import AsyncSession
            self._backend = AsyncSession()
            self._kind = "curl_cffi"
        except ImportError as exc:
            raise BackendUnavailable(
                "no async backend installed (pip install curl_cffi or httpx)") from exc

    @property
    def backend(self):
        self._ensure_backend()
        return self._kind

    def _gate_reason(self, url, quiet=False):
        if self.gate is None:
            return None
        reason = self.gate(url)
        if reason is not None and not quiet and not self._gate_warned:
            self._gate_warned = True
            print(f"[!] Stopping: {reason}")
        return reason

    async def _send(self, method, url, headers=None, **kwargs):
        """The actual backend call, no gate (callers gate first)."""
        self._ensure_backend()
        merged = dict(self.headers)
        merged.update(headers or {})
        try:
            if self._kind == "curl_cffi":
                return await self._backend.request(method, url, timeout=self.timeout,
                                                   headers=merged, **kwargs)
            return await self._backend.request(method, url, headers=merged, **kwargs)
        except Exception as exc:
            print(f"[!] async client: {url} failed ({exc})")
            return None

    async def request(self, method, url, headers=None, **kwargs):
        """One async request (engagement-gated). Returns the response or None."""
        if self._gate_reason(url) is not None:
            return None
        return await self._send(method, url, headers, **kwargs)

    async def get(self, url, **kwargs):
        return await self.request("GET", url, **kwargs)

    async def post(self, url, **kwargs):
        return await self.request("POST", url, **kwargs)

    async def fetch_many(self, urls, concurrency=6, rate=None, on_result=None):
        """Fetch many URLs through a bounded pool.

        `rate` is an optional AIMDRate controller (per-request pacing);
        `on_result(url, response_or_None)` fires as results arrive. A gate
        block (budget exhausted / path excluded) CANCELS the remaining
        candidates instead of pacing them - a budget is not a rate signal.
        Returns {url: response_or_None}.
        """
        cancelled = asyncio.Event()

        async def one(url):
            if cancelled.is_set():
                return url, None
            if self._gate_reason(url, quiet=True) is not None:
                cancelled.set()
                if not self._gate_warned:
                    self._gate_warned = True
                    print("[!] Stopping: remaining candidates skipped "
                          "(engagement limit reached)")
                return url, None
            if rate is not None:
                await asyncio.sleep(rate.delay())
            resp = await self._send("GET", url)
            if rate is not None:
                rate.observe(resp)
            if on_result is not None:
                on_result(url, resp)
            return url, resp

        sem = asyncio.Semaphore(concurrency)

        async def bounded(url):
            async with sem:
                return await one(url)

        pairs = await asyncio.gather(*(bounded(u) for u in urls))
        return dict(pairs)

    async def close(self):
        if self._backend is not None:
            try:
                await self._backend.close()
            except Exception:
                pass


class AIMDRate:
    """Additive-increase/multiplicative-decrease pacing (roadmap stage 1).

    A 429 (or a transport error) doubles the inter-request delay up to
    `max_delay`; every clean answer shrinks it a little toward `min_delay`.
    """

    def __init__(self, min_delay=0.0, max_delay=5.0):
        self.min_delay = min_delay
        self.max_delay = max_delay
        self._delay = min_delay
        self.blocked = 0

    def delay(self):
        return self._delay

    def observe(self, resp):
        if resp is None or getattr(resp, "status_code", 0) == 429:
            self.blocked += 1
            self._delay = min(max(self._delay * 2, 0.05), self.max_delay)
        else:
            self._delay = max(self.min_delay, self._delay * 0.9)


def client_for(url, **kwargs):
    """Pick the sync client for a URL's host (kept for symmetry/future use)."""
    _ = urlsplit(url)
    return SyncClient(**kwargs)
