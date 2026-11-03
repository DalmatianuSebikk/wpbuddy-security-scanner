"""Shared fixtures: full isolation of the scanner's module-level state.

The scanner keeps per-scan state in module globals (soft-404 baselines,
WAF fingerprints, error-page collections, the shared HTTP session,
config.* knobs, the NVD cache). Tests that flip any of those used to leak
into later tests - a WAF test followed by a clean-scan test could report
the first site's firewall for the second one. Every test now runs with
that state snapshotted and restored (P2-11).
"""

import copy

import pytest

from wpbuddy import config, httpclient, vulndb, waf
from wpbuddy.passive import errorpages, files


@pytest.fixture(autouse=True)
def _isolate_scan_state(tmp_path):
    """Reset and later restore every piece of shared scan state."""
    config_snapshot = {key: copy.copy(value) for key, value in vars(config).items()
                       if not key.startswith("__")}
    http_snapshot = {
        "SESSION": httpclient.SESSION,
        "_consecutive_failures": httpclient._consecutive_failures,
        "_rate_limit_backoff": httpclient._rate_limit_backoff,
        "_inspect_warned": httpclient._inspect_warned,
    }

    # vulnerability-cache isolation: never read/write the developer's real
    # ~/.wpbuddy cache from a test (F-1)
    config.VULNDB_CACHE = tmp_path / "vulndb-test.sqlite3"

    files.reset()
    waf.reset()
    errorpages.reset()
    vulndb._nvd_cache.clear()

    yield

    files.reset()
    waf.reset()
    errorpages.reset()
    vulndb._nvd_cache.clear()
    vulndb._nvd_last_fetch = 0.0
    for key, value in http_snapshot.items():
        setattr(httpclient, key, value)
    for key, value in config_snapshot.items():
        setattr(config, key, value)
    for key in list(vars(config)):
        if not key.startswith("__") and key not in config_snapshot:
            delattr(config, key)


@pytest.fixture()
def sent_url_recorder(monkeypatch):
    """Record every URL passing through the HTTP layer, scan-wide.

    Used where behaviour is defined by WHICH requests reach the target
    (e.g. the --stealth contract): patching httpclient.request catches
    everything routed through get/post/get_json alike.
    """
    sent = []
    real_request = httpclient.request

    def recording_request(method, url, **kwargs):
        sent.append(url)
        return real_request(method, url, **kwargs)

    monkeypatch.setattr(httpclient, "request", recording_request)
    return sent
