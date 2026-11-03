"""End-to-end tests against the local mock WordPress site (no real network
except where explicitly noted; vulnerability DB responses are stubbed)."""

import json
import re
import zipfile
from types import SimpleNamespace
from pathlib import Path

import pytest

from mockwp_server import start_mock_wp, VALID_PASSWORD, VALID_USER

from wpbuddy import confidence, httpclient, stealth, versioning, vulndb
from wpbuddy.active import access, credentials, users, xmlrpc
from wpbuddy.codeaudit import analyzer, gather, poc
from wpbuddy.codeaudit.gather import safe_extract_zip
from wpbuddy.passive import content, core_version, files, fingerprints, readme, wprest
from wpbuddy.report import Report


@pytest.fixture(scope="module")
def mock():
    server, base = start_mock_wp(0)
    yield base
    server.shutdown()


@pytest.fixture(autouse=True)
def _isolate_shared_scan_state():
    """The soft-404 baseline cache is keyed by target; tests reuse target
    strings with different fake servers, so start each test clean."""
    files.reset()
    yield
    files.reset()


# ---------------------------------------------------------------- passive

def test_core_version_corroboration(mock):
    """Every method's hit is collected; agreeing sources corroborate to a tier."""
    found = core_version.discover_core_version(mock)
    assert ("6.4.3", "meta-generator", "meta generator tag on the homepage") in found
    assert len(found) >= 2  # the mock also leaks ?ver=, feed generator, readme.html

    resolved = confidence.resolve_core(found)
    assert resolved["version"] == "6.4.3"
    assert resolved["discrepancy"] is False
    assert confidence.tier_for(resolved["score"]) == "CONFIRMED"  # multi-source agreement


def test_crawl_and_discovery(mock):
    pages = content.crawl_page_urls(mock, max_pages=5)
    assert any("/about/" in p for p in pages), "sitemap URL not crawled"

    refs, artifacts = content.discover_refs(pages, mock)
    assert {"contact-form-7", "wpdiscuz"} <= refs["plugins"]   # link href + inline script
    assert "twentytwentythree" in refs["themes"]
    # third-party wp-content URLs are false positives and must be dropped:
    assert "akismet" not in refs["plugins"]            # CSS on cdn.example.net (other domain)
    assert "really-cool-plugin" not in refs["plugins"]  # link to someone-else's WP blog
    assert all(":" not in p for p in refs["plugins"])   # no garbage slugs
    # artifacts feed the fingerprint engine
    assert "woocommerce-active" in artifacts["pages_html"]


def test_same_site_rules():
    from wpbuddy.passive.content import _same_site
    assert _same_site(None, "example.com") is True          # relative URL
    assert _same_site("example.com", "example.com") is True
    assert _same_site("static.example.com", "www.example.com") is True   # own CDN/subdomain
    assert _same_site("example.com", "www.example.com") is True          # apex vs www
    assert _same_site("cdn.example.net", "example.com") is False         # other registrable domain
    assert _same_site("evil-example.com", "example.com") is False        # suffix trick
    # multi-part public suffixes: same .co.uk is NOT the same owner
    assert _same_site("static.example.co.uk", "www.example.co.uk") is True
    assert _same_site("blog.bbc.co.uk", "shop.example.co.uk") is False
    assert _same_site("cdn.example.com.au", "example.com.au") is True


def test_fingerprint_detection(mock):
    """Plugins with no URL traces are found via content fingerprints."""
    pages = content.crawl_page_urls(mock, max_pages=5)
    _, artifacts = content.discover_refs(pages, mock)
    namespaces = wprest.discover_rest_namespaces(mock)
    detected = fingerprints.detect(artifacts, namespaces)

    assert "woocommerce" in detected    # body class, no wp-content URL anywhere
    assert "wpforms-lite" in detected   # [wpforms ...] shortcode on the /about/ page
    assert "contact-form-7" in detected  # REST namespace contact-form-7/v1
    assert "wpdiscuz" in detected        # REST namespace wpdiscuz/v1


def test_readme_versions(mock):
    version, src, kind = readme.find_component_version(mock, "plugins", "contact-form-7")
    assert version == "5.3.1"
    assert "readme.txt" in src
    assert kind == "stable-tag"

    version, src, kind = readme.find_component_version(mock, "themes", "twentytwentythree")
    assert version == "1.1"
    assert "style.css" in src
    assert kind == "style-css"

    version, _, kind = readme.find_component_version(mock, "plugins", "does-not-exist")
    assert version is None and kind is None


def test_readme_versions_reject_soft404_and_challenge(monkeypatch):
    """A host answering every URL with 200 junk must not produce phantom plugin
    versions (and with them phantom CVE matches)."""
    from wpbuddy import httpclient
    monkeypatch.setattr(httpclient, "get", _fake_soft404_server({
        # a challenge page that happens to contain version-looking numbers
        "readme.txt": FakeResp(200, "<html><title>One moment, please</title>"
                                     "<body>wp-content 6.4.3 assets</body></html>"),
    }))
    version, _, _ = readme.find_component_version("https://soft404.example.com/",
                                                  "plugins", "foo")
    assert version is None


def test_readme_anchor_ignores_php_and_wp_requirements():
    """'Requires PHP 7.4' / 'WordPress 6.0' are environment facts, not the
    plugin's version - the first bare number after the anchor wins."""
    text = ("=== Demo ===\n== Installation ==\n"
            "Requires PHP 7.4 and WordPress 6.0.\n== Features ==\n3.2 widget")
    assert readme._version_from_readme(text) == ("3.2", "changelog-anchor")


def test_rest_discovery(mock):
    namespaces = wprest.discover_rest_namespaces(mock)
    assert "contact-form-7/v1" in namespaces
    assert "wp/v2" not in namespaces  # core namespaces filtered out

    users = wprest.users_via_rest_collection(mock)
    assert ("Admin Site", "adminsite") in users


def test_sensitive_files_and_headers(mock):
    report = Report()
    files.check_sensitive_files(report, mock)
    text = report.doc.write()
    assert "debug.log" in text
    assert "readme.html" in text  # both are served as 200 by the mock

    report = Report()
    files.check_headers(report, mock)
    text = report.doc.write()
    # the mock sends no security headers at all - all must be reported missing
    for header in files.SECURITY_HEADERS:
        assert header in text
    assert "PHP/8.2.0" in text  # technology disclosure


class FakeResp:
    def __init__(self, status, body="", location=None, url=""):
        self.status_code = status
        self.text = body
        self.content = body.encode()
        self.headers = {"Location": location} if location else {}
        self.url = url


SOFT_404_BODY = "<html><body><h1>Oops, nothing here</h1><p>page not found</p></body></html>"


def _fake_soft404_server(responses):
    """httpclient.get that answers like a soft-404 host: unknown paths -> 200 junk."""
    def fake_get(url, **kwargs):
        if "wpbuddy-" in url:            # baseline probes
            return FakeResp(200, SOFT_404_BODY)
        for suffix, resp in responses.items():
            if url.endswith(suffix):
                return resp
        return FakeResp(200, SOFT_404_BODY)  # catch-all: everything "exists" as 200
    return fake_get


def test_sensitive_files_soft404_no_false_positives(monkeypatch):
    """A catch-all 200 host must not make every probe 'reachable'."""
    from wpbuddy import httpclient
    monkeypatch.setattr(httpclient, "get", _fake_soft404_server({
        ".env": FakeResp(301, "", location="https://site.example.com/"),
    }))
    report = Report()
    files.check_sensitive_files(report, "https://site.example.com/")
    text = report.doc.write()
    assert "CONFIRMED exposed" not in text
    assert "possible exposure" not in text
    assert "None of the common sensitive files" in text


def test_sensitive_files_signature_confirms_real_leak(monkeypatch):
    """A wp-config backup with real content is CONFIRMED, with evidence."""
    from wpbuddy import httpclient
    monkeypatch.setattr(httpclient, "get", _fake_soft404_server({
        "wp-config.php.bak": FakeResp(
            200, "<?php define('DB_NAME', 'wp'); define('DB_PASSWORD', 'hunter2');"),
    }))
    report = Report()
    files.check_sensitive_files(report, "https://site.example.com/")
    text = report.doc.write()
    assert "CONFIRMED exposed: `wp-config.php.bak`" in text
    assert "WordPress DB credentials" in text
    assert "hunter2" not in text  # secrets are never echoed into the report


def test_sensitive_files_protected_and_unreachable(monkeypatch):
    """403 = exists-but-protected note; honest 404 = silent."""
    from wpbuddy import httpclient
    monkeypatch.setattr(httpclient, "get", lambda url, **kw: FakeResp(404))
    report = Report()
    files.check_sensitive_files(report, "https://site.example.com/")
    assert "None of the common sensitive files" in report.doc.write()


def test_sensitive_files_blanket_403_rule(monkeypatch):
    """A WAF denying every .env/.git-ish path is hardening, not evidence of files."""
    from wpbuddy import httpclient

    def fake_get(url, **kwargs):
        return FakeResp(404) if "wpbuddy-" in url and ".html" in url else FakeResp(403)

    monkeypatch.setattr(httpclient, "get", fake_get)
    report = Report()
    files.check_sensitive_files(report, "https://site.example.com/")
    text = report.doc.write()
    assert "denies these paths wholesale" in text
    assert "NOT evidence the files exist" in text
    assert "often means the file exists" not in text  # no more per-file overclaims


def test_sensitive_files_waf_challenge_200(monkeypatch):
    """The ecommedbt.ro failure: a Cloudflare 'One moment, please...' interstitial
    served with HTTP 200 on every URL must not turn into 9 'possible exposure'."""
    from wpbuddy import httpclient

    def fake_get(url, **kwargs):
        return FakeResp(200, "<html><head><title>One moment, please...</title>"
                             "<script>window.location.reload()</script></head></html>")

    monkeypatch.setattr(httpclient, "get", fake_get)
    report = Report()
    files.check_sensitive_files(report, "https://site.example.com/")
    text = report.doc.write()
    assert "possible exposure" not in text
    assert "CONFIRMED exposed" not in text
    assert "None of the common sensitive files" in text


def test_sensitive_files_backup_archive_magic(monkeypatch):
    """A 200 backup.zip that really is a ZIP (PK magic) is CONFIRMED, not just
    'reachable' - an HTML soft-404 with the same name is not."""
    from wpbuddy import httpclient

    def fake_get(url, **kwargs):
        if url.endswith("backup.zip"):
            resp = FakeResp(200, "\u0000binary\u0000")
            resp.content = b"PK\x03\x04" + b"\x00" * 100   # real ZIP magic bytes
            return resp
        if "wpbuddy-" in url:
            return FakeResp(404)
        return FakeResp(404)

    monkeypatch.setattr(httpclient, "get", fake_get)
    report = Report()
    files.check_sensitive_files(report, "https://site.example.com/")
    text = report.doc.write()
    assert "CONFIRMED exposed: `backup.zip`" in text
    assert "ZIP archive" in text


def test_setup_wizard_check(monkeypatch):
    from wpbuddy import httpclient

    def wizard(body):
        monkeypatch.setattr(httpclient, "get",
                            lambda url, **kw: FakeResp(200, body) if "setup-config" in url
                            else FakeResp(404))
        report = Report()
        files.check_setup_wizard(report, "https://site.example.com/")
        return report.doc.write()

    assert "Setup wizard reachable" in wizard(
        '<form method="post"><input name="dbname" /><input name="uname" /></form>')
    # installed site politely refusing: the normal, safe case - no finding
    assert "Setup wizard reachable" not in wizard(
        "<p>The file 'wp-config.php' already exists.</p>")


def test_sensitive_files_dynamic_page_drift(monkeypatch):
    """Challenge pages that change size every request (ray ids, timestamps) still
    match the baseline: the old +/-48 byte tolerance missed the ~100-byte drift."""
    from wpbuddy import httpclient
    import itertools

    counter = itertools.count()

    def fake_get(url, **kwargs):
        n = next(counter)
        # bounded per-request jitter (a few tokens), not unbounded growth
        jitter = (n % 5) * 40
        return FakeResp(200, "<html><body>interstitial " + "y" * (12000 + jitter) + "</body></html>")

    monkeypatch.setattr(httpclient, "get", fake_get)
    report = Report()
    files.check_sensitive_files(report, "https://site.example.com/")
    text = report.doc.write()
    assert "possible exposure" not in text
    assert "None of the common sensitive files" in text


def test_robots_filters_default_entries(mock):
    report = Report()
    files.check_robots(report, mock)
    text = report.doc.write()
    assert "/secret-staging/" in text          # genuinely interesting entry
    assert "/wp-admin/" not in text.split("Interesting")[1]  # default dropped


def test_robots_empty_disallow_does_not_capture_next_line(monkeypatch):
    """The Yoast block ('Disallow:' with no value, then 'Sitemap:') once made
    'Sitemap:' appear as an interesting disallowed path."""
    from wpbuddy import httpclient

    yoast = ("# START YOAST BLOCK\nUser-agent: *\nDisallow:\n\n"
             "Sitemap: https://site.example.com/sitemap_index.xml\n# END YOAST BLOCK\n")
    monkeypatch.setattr(httpclient, "get",
                        lambda url, **kw: FakeResp(200, yoast) if "robots.txt" in url
                        else FakeResp(404))
    report = Report()
    files.check_robots(report, "https://site.example.com/")
    text = report.doc.write()
    # the raw robots.txt body is echoed verbatim (it contains 'Sitemap:'); the
    # bug was Sitemap leaking into the interesting-DISALLOW list
    if "Interesting" in text:
        assert "Sitemap:" not in text.split("Interesting", 1)[1]


def test_security_txt_check(monkeypatch):
    from wpbuddy import httpclient

    def server(body_by_path):
        def fake_get(url, **kw):
            for suffix, body in body_by_path.items():
                if url.endswith(suffix):
                    return FakeResp(200, body)
            return FakeResp(404)
        return fake_get

    # published with a contact -> positive finding
    monkeypatch.setattr(httpclient, "get", server({
        "security.txt": "Contact: mailto:security@example.com\nExpires: 2027-01-01T00:00:00Z"}))
    report = Report()
    files.check_security_txt(report, "https://site.example.com/")
    text = report.doc.write()
    assert "security.txt" in text and "security@example.com" in text

    # a 200 challenge page must not count as a security.txt
    monkeypatch.setattr(httpclient, "get", server({
        "security.txt": "<html><title>One moment, please</title></html>"}))
    report = Report()
    files.check_security_txt(report, "https://site.example.com/")
    assert "security.txt is published" not in report.doc.write()

    # absent -> nothing reported (absence is the norm, not a finding)
    monkeypatch.setattr(httpclient, "get", server({}))
    report = Report()
    files.check_security_txt(report, "https://site.example.com/")
    assert "security.txt" not in report.doc.write()


# ---------------------------------------------------------------- error page analysis

# a real Wordfence/dp-preloader fatal page observed on a hardened WordPress site
ECOMEDBT_TRACE = (
    'Fatal error: Uncaught Error: Undefined constant "ET_FB_ENABLED" in '
    '/home/ecomedbt/public_html/wp-content/plugins/dp-preloader/dp-preloader.php:507 '
    'Stack trace: #0 /home/ecomedbt/public_html/wp-includes/class-wp-hook.php(353): '
    "dppre_loader_html('') #9 /home/ecomedbt/public_html/wp-content/plugins/wordfence/lib/"
    "wordfenceClass.php(7570): include('/home/ecomedbt/...') #10 "
    "wordfence::preventAuthorNScans(Array) #4 /home/ecomedbt/public_html/wp-content/themes/"
    "Divi/header.php(27): wp_head() thrown in /home/ecomedbt/public_html/wp-content/plugins/"
    "dp-preloader/dp-preloader.php on line 507"
)


def test_errorpage_analysis_real_trace():
    from wpbuddy.passive import errorpages
    errorpages.reset()
    errorpages.inspect(FakeResp(500, ECOMEDBT_TRACE, url="https://ecomedbt.ro/?author=1"))
    errorpages.inspect(FakeResp(500, ECOMEDBT_TRACE, url="https://ecomedbt.ro/?author=2"))

    assert errorpages.discovered_plugins() == {"dp-preloader", "wordfence"}
    assert errorpages.discovered_themes() == {"Divi"}
    entry = errorpages.entries()[0]
    assert entry["paths"] == ["/home/ecomedbt/public_html/"]
    assert entry["count"] == 2  # identical pages deduped with a counter
    assert any("Wordfence" in n for n in entry["notes"])
    assert any("author-enumeration blocking" in n for n in entry["notes"])


def test_errorpage_ignores_release_notes_mentioning_errors():
    """A changelog saying 'fixed a fatal error in x.php' is not an error page."""
    from wpbuddy.passive import errorpages
    errorpages.reset()
    changelog = ("version 4.27.7 ( updated 05-12-2026 ) | - Security Update: Fixed a "
                 "fatal error in builder.php rendering; improved compatibility with "
                 "wp-simple-firewall and sucuri plugins")
    errorpages.inspect(FakeResp(200, changelog, url="https://x.example.com/changelog.txt"))
    assert errorpages.entries() == []  # no file:line structure, no collection


def test_errorpage_report_section(monkeypatch):
    from wpbuddy.passive import errorpages
    errorpages.reset()
    monkeypatch.setattr(vulndb, "plugin_lookup", lambda slug: ([{"fake": 1}], "ok"))
    errorpages.inspect(FakeResp(500, ECOMEDBT_TRACE, url="https://ecomedbt.ro/?author=1"))
    report = Report()
    errorpages.write_report(report, known_plugins={"wordfence"})
    text = report.doc.write()
    assert "server path disclosed: `/home/ecomedbt/public_html/`" in text
    assert "**dp-preloader**" in text and "1 recorded vulnerabilities" in text
    assert "Wordfence" in text


def test_errorpage_no_disclosure_honest_intro(monkeypatch):
    """A bare HTML 500 with nothing recognizable must not be introduced as
    'discloses server paths, components, defensive layers'."""
    from wpbuddy.passive import errorpages
    errorpages.reset()
    errorpages.inspect(FakeResp(500, "<html><body>error</body></html>",
                                url="https://site.example.com/oops"))
    report = Report()
    errorpages.write_report(report)
    text = report.doc.write()
    assert "None of them contained recognizable disclosure" in text
    assert "discloses server paths" not in text


def test_no_retry_storm_on_server_errors(monkeypatch):
    """A 5xx is the server's answer - it must be returned on the first attempt."""
    calls = []

    class FakeSession:
        def request(self, method, url, **kwargs):
            calls.append(url)
            return FakeResp(500, ECOMEDBT_TRACE)

    monkeypatch.setattr(httpclient, "SESSION", FakeSession())
    resp = httpclient.get("https://site.example.com/?author=1")
    assert resp.status_code == 500
    assert len(calls) == 1  # no retry, no sleep storm


def test_rate_limited_429_no_evasion(monkeypatch):
    """A 429 must make the scanner QUIETER: no path-variant escalation."""
    from wpbuddy import obfuscate, waf
    waf.reset()
    calls = []
    monkeypatch.setattr(httpclient, "get",
                        lambda url, **kw: (calls.append(url), FakeResp(429))[1])
    resp, technique = obfuscate.fetch_first_allowed(
        "https://site.example.com/wp-content/plugins/x/readme.txt")
    assert resp.status_code == 429
    assert technique is None
    assert len(calls) == 1            # exactly one request - no 5-variant ladder
    assert waf.bypass_events() == {}  # and nothing counted as a "bypass"


def test_rate_limited_429_arms_escalating_cooldown(monkeypatch):
    """429s arm a scan-wide cool-down that honours Retry-After and resets on success."""
    monkeypatch.setattr(httpclient, "_rate_limit_backoff", 0.0)
    monkeypatch.setattr("time.sleep", lambda s: None)

    class RateLimitedSession:
        def request(self, method, url, **kwargs):
            resp = FakeResp(429, "slow down")
            resp.headers = {"Retry-After": "7"}
            return resp

    monkeypatch.setattr(httpclient, "SESSION", RateLimitedSession())
    assert httpclient.get("https://site.example.com/").status_code == 429
    assert httpclient.RATE_LIMIT_MIN_BACKOFF <= httpclient._rate_limit_backoff >= 7.0

    sleeps = []
    monkeypatch.setattr("time.sleep", lambda s: sleeps.append(s))
    httpclient.get("https://site.example.com/")   # next request cools down first
    assert sleeps and max(sleeps) >= 7.0

    class OkSession:
        def request(self, method, url, **kwargs):
            return FakeResp(200, "fine")

    monkeypatch.setattr(httpclient, "SESSION", OkSession())
    httpclient.get("https://site.example.com/")
    assert httpclient._rate_limit_backoff == 0.0  # a real answer clears the backoff


def test_circuit_breaker_single_attempt(monkeypatch):
    """After consecutive network failures the promised 'single attempts' happen:
    one attempt per request until a response gets through again."""
    monkeypatch.setattr(httpclient, "_consecutive_failures", 0)
    monkeypatch.setattr("time.sleep", lambda s: None)
    calls = []

    class DeadSession:
        def request(self, method, url, **kwargs):
            calls.append(url)
            raise ConnectionError("host down")

    monkeypatch.setattr(httpclient, "SESSION", DeadSession())
    for _ in range(5):
        assert httpclient.get("https://site.example.com/") is None
    assert len(calls) == 15            # 5 requests x 3 retries each
    assert httpclient.get("https://site.example.com/") is None
    assert len(calls) == 16            # 6th request: exactly ONE attempt


def test_waf_bypass_not_counted_for_error_pages(monkeypatch):
    """A variant that slips past the WAF but hits a 404 is returned as data,
    yet must not inflate the 'obfuscation got through' report stats."""
    from wpbuddy import obfuscate, waf
    waf.reset()
    calls = []

    def fake_get(url, **kw):
        calls.append(url)
        return FakeResp(403) if len(calls) == 1 else FakeResp(404)

    monkeypatch.setattr(httpclient, "get", fake_get)
    resp, technique = obfuscate.fetch_first_allowed(
        "https://site.example.com/wp-content/plugins/x/readme.txt")
    assert resp.status_code == 404 and technique is not None
    assert len(calls) == 2             # plain (blocked) + one variant
    assert waf.bypass_events() == {}   # a 404 is not a firewall "win"


def test_waf_detection_ignores_third_party_responses(monkeypatch):
    """A firewall on wpvulnerability.net/NVD (which the scanner also queries)
    must never be reported as the TARGET's WAF - found by the 0.3.0 mock test."""
    from wpbuddy import config, waf
    waf.reset()
    monkeypatch.setattr(config, "TARGET_HOST", "site.example.com")

    imperva_body = "<html>Request unsuccessful. Incapsula</html>"
    waf.inspect_response(FakeResp(200, imperva_body, url="https://www.wpvulnerability.net/plugin/x/"))
    assert waf.detected() == []                       # third-party host: ignored

    waf.inspect_response(FakeResp(200, imperva_body, url="https://site.example.com/page"))
    assert "Imperva/Incapsula" in waf.detected()      # same host: counted
    waf.reset()
    monkeypatch.setattr(config, "TARGET_HOST", None)


def test_author_enum_aborts_on_erroring_site(monkeypatch):
    """Author probing must stop after a few consecutive errors, not grind 25 ids."""
    calls = []

    def fake_get(url, **kwargs):
        calls.append(url)
        return FakeResp(500, ECOMEDBT_TRACE, url=url)

    monkeypatch.setattr(httpclient, "get", fake_get)
    found = users._enumerate_via_author_redirects("https://site.example.com/", max_ids=25)
    assert found == []
    assert len(calls) == 3  # aborted early instead of 25 x 3-attempt storms


# ---------------------------------------------------------------- WAF awareness & evasion

def test_path_variants_ladder():
    from wpbuddy import obfuscate
    variants = dict(obfuscate.path_variants("/wp-content/plugins/x/readme.txt"))
    assert variants["dot-segment"] == "/./wp-content/plugins/x/readme.txt"
    assert variants["double-slash"] == "//wp-content/plugins/x/readme.txt"
    assert variants["semicolon-segment"] == "/wp-content;/plugins/x/readme.txt"
    assert "%2f" in variants["percent-slash"]
    assert variants["case-flip"].startswith("/Wp-content/Plugins/")


def test_waf_detection_and_bypass(mock):
    """Mock WAF blocks plain readme probes; a variant must get through."""
    from wpbuddy import obfuscate, waf
    waf.reset()
    resp, technique = obfuscate.fetch_first_allowed(
        f"{mock}wp-content/plugins/contact-form-7/readme.txt")
    assert resp is not None and resp.status_code == 200
    assert technique is not None                       # plain was blocked
    assert "Cloudflare" in waf.detected()
    assert waf.bypass_events().get(technique, 0) >= 1

    report = Report()
    waf.write_report(report)
    text = report.doc.write()
    assert "Cloudflare" in text and technique in text


def test_waf_version_crawling_survives_blocks(mock):
    """readme.txt/style.css versions must still resolve behind the WAF."""
    from wpbuddy import waf
    waf.reset()
    version, src, _kind = readme.find_component_version(mock, "plugins", "contact-form-7")
    assert version == "5.3.1" and "readme.txt" in src
    version, src, _kind = readme.find_component_version(mock, "themes", "twentytwentythree")
    assert version == "1.1" and "style.css" in src
    assert waf.bypass_events()  # the ladder did the work


def test_no_evade_flag_respected(mock, monkeypatch):
    from wpbuddy import config, obfuscate, waf
    waf.reset()
    monkeypatch.setattr(config, "EVADE", False)
    resp, technique = obfuscate.fetch_first_allowed(
        f"{mock}wp-content/plugins/contact-form-7/readme.txt")
    assert resp is not None and resp.status_code == 403  # left blocked
    assert technique is None and not waf.bypass_events()


def test_robots_disallow_extraction(mock):
    report = Report()
    files.check_robots(report, mock)
    assert "/secret-staging/" in report.doc.write()


# ---------------------------------------------------------------- active

def test_author_redirect_enumeration(mock):
    found = users._enumerate_via_author_redirects(mock, max_ids=3)
    slugs = [slug for _, slug in found]
    assert "adminsite" in slugs


def test_xmlrpc_probe(mock):
    report = Report()
    assert xmlrpc.probe(report, mock) is True
    text = report.doc.write()
    assert "system.multicall" in text
    assert "pingback.ping" in text


def test_xmlrpc_multicall_bruteforce(mock):
    report = Report()
    passwords = ["wrong1", "wrong2", VALID_PASSWORD]
    assert xmlrpc.bruteforce(report, mock, VALID_USER, passwords) == VALID_PASSWORD
    assert xmlrpc.bruteforce(report, mock, VALID_USER, ["nope"]) is None


def test_multicall_parses_real_wordpress_shape():
    """Real WordPress multicall: successes in <array> wrappers, faults as bare
    <struct>s. The old single-regex parser miscounted mixed batches like this
    one and silently discarded the found credential."""
    response = ('<?xml version="1.0"?><methodResponse><params><param><value><array><data>'
                "<value><struct>"
                '<member><name>faultCode</name><value><int>403</int></value></member>'
                '<member><name>faultString</name><value><string>Incorrect username or password.</string></value></member>'
                "</struct></value>"
                "<value><array><data><value><struct>"
                '<member><name>url</name><value><string>http://mock/</string></value></member>'
                '<member><name>blogName</name><value><string>Mock</string></value></member>'
                "</struct></value></data></array></value>"
                "<value><struct>"
                '<member><name>faultCode</name><value><int>403</int></value></member>'
                "</struct></value>"
                "</data></array></value></param></params></methodResponse>")
    items = xmlrpc._multicall_items(response)
    assert items is not None and len(items) == 3
    pairs = [("admin", "wrong"), ("admin", VALID_PASSWORD), ("admin", "nope")]
    found = {(u, p) for (u, p), item in zip(pairs, items) if not xmlrpc.FAULT_RE.search(item)}
    assert found == {("admin", VALID_PASSWORD)}
    # non-multicall bodies (error pages) are rejected, not mis-parsed
    assert xmlrpc._multicall_items("<html>Access denied</html>") is None


def test_dictionary_attack(mock):
    report = Report()
    passwords = ["1234567", VALID_PASSWORD, "salut"]
    found = credentials.dictionary_attack(report, mock, VALID_USER, passwords)
    assert found == VALID_PASSWORD
    assert credentials.dictionary_attack(report, mock, VALID_USER, ["not-in-list"]) is None


# ---------------------------------------------------------------- vulndb (stubbed)

def test_is_affected_operators():
    lt = {"max_version": "5.3.2", "max_operator": "lt", "min_version": None, "min_operator": None}
    assert vulndb.is_affected("5.3.1", lt) == (True, "bounded")
    assert vulndb.is_affected("5.3.2", lt) == (False, "bounded")
    assert vulndb.is_affected("6.0", lt) == (False, "bounded")

    le = {"max_version": "5.3.2", "max_operator": "le"}
    assert vulndb.is_affected("5.3.2", le) == (True, "bounded")

    ranged = {"min_version": "2.0", "min_operator": "ge", "max_version": "3.0", "max_operator": "lt"}
    assert vulndb.is_affected("1.5", ranged) == (False, "bounded")  # below range - old code flagged this
    assert vulndb.is_affected("2.5", ranged) == (True, "bounded")
    assert vulndb.is_affected("3.5", ranged) == (False, "bounded")

    unfixed = {"max_version": "0.3.6", "max_operator": "le", "unfixed": "1"}
    assert vulndb.is_affected("9.9", unfixed) == (True, "unfixed")  # above max but unfixed

    # no operator data at all: still reported, but labelled as an assumption
    assert vulndb.is_affected("9.9", {}) == (True, "assumed")
    assert vulndb.is_affected("9.9", None) == (True, "assumed")


def test_affected_vulnerabilities_dedup():
    vulns = [
        {"operator": {"max_version": "5.3.2", "max_operator": "lt"},
         "source": [{"name": "CVE-2020-35489", "description": "file upload issue"}]},
        {"operator": {"max_version": "5.3.1", "max_operator": "le"},
         "source": [{"name": "CF7 file upload", "description": "file upload issue"}]},  # same desc
        {"operator": {"max_version": "5.8.3", "max_operator": "le"},
         "source": [{"name": "CVE-2023-6449", "description": "different issue"}]},
    ]
    affected = vulndb.affected_vulnerabilities("5.3.1", vulns)
    assert len(affected) == 2  # dedup worked (the old code never deduplicated)
    assert {v["basis"] for v in affected} == {"bounded"}


def test_advisory_junk_names_replaced():
    """A Wordfence page scraped as '404 Page Not Found' must never be a title."""
    vulns = [
        {"operator": {"unfixed": "1"},
         "source": [{"name": "404 Page Not Found",
                     "link": "https://www.wordfence.com/threat-intel/vulnerabilities/x/y/z"}]},
        {"operator": {"unfixed": "1"},
         "source": [{"name": "Access Denied | Sucuri",
                     "link": "https://www.cve.org/CVERecord?id=CVE-2026-65498"}]},
    ]
    affected = vulndb.affected_vulnerabilities("3.2.0", vulns)
    names = [v["name"] for v in affected]
    assert names[0].startswith("Unnamed advisory")   # no CVE in the link -> placeholder
    assert names[1] == "CVE-2026-65498 (advisory title unreadable)"


def test_advisory_title_contradiction_demotes():
    """The Complianz false positive: 'unfixed' flag vs title saying '<= 7.5.0'
    while the site runs 7.5.5 - demoted to 'contradicted', not dropped."""
    vulns = [{
        "operator": {"unfixed": "1"},
        "source": [{"name": "WordPress Complianz plugin <= 7.5.0 - PHP Object Injection vulnerability",
                    "description": "object injection"}],
    }]
    affected = vulndb.affected_vulnerabilities("7.5.5", vulns)
    assert affected[0]["basis"] == "contradicted"
    # and the confidence model punishes it hard
    score = confidence.score(["page-reference", "enum-200"], "stable-tag", "contradicted")
    assert confidence.tier_for(score) == "UNVERIFIED"

    # same advisory, site on the affected version: no contradiction
    affected = vulndb.affected_vulnerabilities("7.5.0", vulns)
    assert affected[0]["basis"] == "unfixed"

    # '< X' / 'X and earlier' forms
    lt = [{"operator": {"unfixed": "1"},
           "source": [{"name": "Plugin < 4.0 - SSRF", "description": "ssrf"}]}]
    assert vulndb.affected_vulnerabilities("4.0", lt)[0]["basis"] == "contradicted"
    earlier = [{"operator": {"unfixed": "1"},
                "source": [{"name": "Plugin 3.1.3 and earlier - auth bypass", "description": "d"}]}]
    assert vulndb.affected_vulnerabilities("3.2.0", earlier)[0]["basis"] == "contradicted"
    assert vulndb.affected_vulnerabilities("3.1.3", earlier)[0]["basis"] == "unfixed"


def test_bounds_parsed_from_descriptions():
    """The FP class that survived 0.3.0's title-only parser: bounds stated in
    the DESCRIPTION body (bare CVE names carry them there)."""
    # CVE-2026-65498 shape: bare CVE title, bound only in the description
    desc_only = [{"operator": {"unfixed": "1"},
                  "source": [{"name": "CVE-2026-65498",
                              "description": "[en] Unauthenticated Sensitive Data "
                                             "Exposure in Complianz <= 7.5.0 versions."}]}]
    assert vulndb.affected_vulnerabilities("7.5.5", desc_only)[0]["basis"] == "contradicted"
    assert vulndb.affected_vulnerabilities("7.5.0", desc_only)[0]["basis"] == "unfixed"

    # CVE-2026-93485 shape: full range list in prose; installed is the fixed boundary
    range_list = [{"operator": {},
                   "source": [{"name": "CVE-2026-93485",
                               "description": "This issue affects WordPress versions "
                                              "7.1 before 7.1.1; 7.0 through 7.0.4; "
                                              "6.4 through 6.4.10; 5.9 through 5.9.16."}]}]
    assert vulndb.affected_vulnerabilities("7.1.1", range_list)[0]["basis"] == "contradicted"
    assert vulndb.affected_vulnerabilities("6.4.5", range_list)[0]["basis"] != "contradicted"

    # a bound that could still include the version suppresses the verdict
    mixed = [{"operator": {"unfixed": "1"},
              "source": [{"name": "X", "description": "fixed in 7.5.1; reintroduced 8.0 "
                                                      "through 8.0.1"}]}]
    assert vulndb.affected_vulnerabilities("7.5.5", mixed)[0]["basis"] == "unfixed"


def test_advisory_junk_name_keeps_real_error_titles():
    """'Error Log Viewer <= 2.1 - XSS' is a legitimate advisory name, not a
    scraped 404 page - the junk filter must be phrase-tight."""
    vulns = [{"operator": {"unfixed": "1"},
              "source": [{"name": "Error Log Viewer <= 2.1 - Stored XSS",
                          "description": "stored xss via log viewer"}]}]
    name = vulndb.affected_vulnerabilities("2.1", vulns)[0]["name"]
    assert name == "Error Log Viewer <= 2.1 - Stored XSS"


def test_advisory_url_slug_bounds():
    """Wordfence encodes the affected ceiling in the URL slug
    ('...-custom-post-order-313-...' = <= 3.1.3); a garbage advisory name
    with a slug-bounded link must still be contradicted."""
    url = ("https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-plugins/"
           "intuitive-custom-post-order/"
           "intuitive-custom-post-order-313-missing-authorization-to-authenticated-settings-change")
    vulns = [{"operator": {"unfixed": "1"},
              "source": [{"name": "404 Page Not Found", "link": url}]}]
    out = vulndb.affected_vulnerabilities("3.2.0", vulns, slug="intuitive-custom-post-order")
    assert out[0]["basis"] == "contradicted"   # 3.2.0 > 3.1.3
    out = vulndb.affected_vulnerabilities("3.1.2", vulns, slug="intuitive-custom-post-order")
    assert out[0]["basis"] == "unfixed"        # inside the bound
    # numbers NOT anchored to the slug (ids, dates) must not create bounds
    loose = [{"operator": {"unfixed": "1"},
              "source": [{"name": "X", "link": "https://example.com/2026/05/id-99871-advisory"}]}]
    assert vulndb.affected_vulnerabilities("9.9", loose, slug="x")[0]["basis"] == "unfixed"


# ---------------------------------------------------------------- NVD enrichment

NVD_PAYLOAD = {"vulnerabilities": [{"cve": {
    "configurations": [{"nodes": [{"cpeMatch": [{
        "criteria": "cpe:2.3:a:wordpress:wordpress:*:*:*:*:*:*:*",
        "versionStartIncluding": "7.1",
        "versionEndExcluding": "7.1.2",
    }]}]}],
    "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 7.4, "baseSeverity": "HIGH"}}]},
}}]}


def test_nvd_operator_parsed_from_cpe_ranges():
    operators = vulndb._nvd_parse_operator(NVD_PAYLOAD)
    assert operators == [{"min_version": "7.1", "min_operator": "ge",
                           "max_version": "7.1.2", "max_operator": "lt"}]
    # a plugin CPE under the same CVE must not bound CORE applicability
    plugin_only = {"vulnerabilities": [{"cve": {"configurations": [{"nodes": [{"cpeMatch": [{
        "criteria": "cpe:2.3:a:coolplugin:coolplugin:1.0:*:*:*:*:*:*:*",
    }]}]}]}}]}
    assert vulndb._nvd_parse_operator(plugin_only) is None
    assert vulndb._nvd_severity(NVD_PAYLOAD) == "7.4 (high)"


def test_nvd_enrichment_bounds_and_refutes(monkeypatch):
    """'assumed' core CVEs become bounded or refuted via NVD's version ranges."""
    vulndb._nvd_cache.clear()
    monkeypatch.setattr(vulndb.time, "sleep", lambda s: None)  # no rate-limit waits

    def fake_operator(cve_id):
        return [{"min_version": "7.1", "min_operator": "ge",
                 "max_version": "7.1.2", "max_operator": "lt"}]

    monkeypatch.setattr(vulndb, "_nvd_operator", fake_operator)
    vulns = [
        {"name": "CVE-2026-93485", "description": "core issue", "link": "", "severity": None,
         "basis": "assumed"},
        {"name": "Some other advisory", "description": "no cve id", "link": "",
         "severity": None, "basis": "assumed"},
    ]
    out = vulndb.enrich_core_with_nvd("7.1.1", vulns)
    assert out[0]["basis"] == "bounded"    # 7.1 <= 7.1.1 < 7.1.2
    assert out[1]["basis"] == "assumed"    # no CVE id -> left alone

    out = vulndb.enrich_core_with_nvd("7.2.0", [
        {"name": "CVE-2026-93485", "description": "core issue", "link": "",
         "severity": None, "basis": "assumed"}])
    assert out[0]["basis"] == "refuted"    # above the range


def test_nvd_disjoint_cpe_ranges_all_evaluated(monkeypatch):
    """The P0-5 repro: first range '< 6.5.0', second '6.6.0 - < 6.7.0'.
    An installed 6.6.8 is covered by the second range and must be bounded;
    the old first-match-only logic refuted it."""
    payload = {"vulnerabilities": [{"cve": {"configurations": [{"nodes": [{"cpeMatch": [
        {"criteria": "cpe:2.3:a:wordpress:wordpress:*:*:*:*:*:*:*",
         "versionEndExcluding": "6.5.0"},
        {"criteria": "cpe:2.3:a:wordpress:wordpress:*:*:*:*:*:*:*",
         "versionStartIncluding": "6.6.0", "versionEndExcluding": "6.7.0"},
    ]}]}]}}]}
    operators = vulndb._nvd_parse_operator(payload)
    assert len(operators) == 2

    vulndb._nvd_cache.clear()
    monkeypatch.setattr(vulndb, "_nvd_operator", lambda cve_id: operators)

    def vuln():
        return {"name": "CVE-2026-54321", "description": "d", "link": "",
                "severity": None, "basis": "assumed"}

    assert vulndb.enrich_core_with_nvd("6.6.8", [vuln()])[0]["basis"] == "bounded"
    assert vulndb.enrich_core_with_nvd("6.4.9", [vuln()])[0]["basis"] == "bounded"
    assert vulndb.enrich_core_with_nvd("6.5.5", [vuln()])[0]["basis"] == "refuted"  # outside every range


def test_nvd_operator_network_failure_keeps_assumed(monkeypatch):
    """NVD being down must not change the finding - the scan never depends on it."""
    vulndb._nvd_cache.clear()
    monkeypatch.setattr(vulndb.time, "sleep", lambda s: None)
    monkeypatch.setattr(httpclient, "get", lambda url, **kw: None)
    assert vulndb._nvd_operator("CVE-2026-93485") is None


# ---------------------------------------------------------------- confidence model

def test_dangling_references_reported(monkeypatch):
    """External hosts that no longer resolve while still linked = broken-link
    hijack signal; same-site subdomains and infra hosts are not flagged."""
    from wpbuddy.passive import dangling
    monkeypatch.setattr(dangling, "_resolves", lambda h: h != "assets.expired-vendor.example.org")
    report = Report()
    dangling.check(report, "https://site.example.com/",
                   '<a href="https://assets.expired-vendor.example.org/logo.png">logo</a>'
                   '<img src="https://assets.expired-vendor.example.org/banner.png">'
                   '<script src="https://cdn.site.example.com/app.js"></script>'
                   '<a href="https://www.w3.org/standards">spec</a>')
    section = report.doc.write().split("Dangling external references", 1)[1]
    assert "assets.expired-vendor.example.org" in section
    assert "referenced 2x" in section
    assert "cdn.site.example.com" not in section   # same-site subdomain
    assert "w3.org" not in section                 # infra skip-list


def test_dangling_none_when_all_resolve(monkeypatch):
    from wpbuddy.passive import dangling
    monkeypatch.setattr(dangling, "_resolves", lambda h: True)
    report = Report()
    dangling.check(report, "https://site.example.com/", '<a href="https://fine.example.net/">x</a>')
    assert "Dangling external references" not in report.doc.write()


def test_confidence_score_and_tiers():
    # readme on target + page reference + explicit Stable tag + bounded range
    high = confidence.score(["readme-200", "page-reference"], "stable-tag", "bounded")
    assert confidence.tier_for(high) == "CONFIRMED"

    # fingerprint alone, version unknown: a heuristic lead
    assert confidence.tier_for(confidence.score(["fingerprint"])) == "UNVERIFIED"

    # two independent presence sources push a fingerprint to LIKELY
    assert confidence.tier_for(confidence.score(["fingerprint", "page-reference"])) == "LIKELY"

    # page mention + anchor-scraped version + no advisory range data: assumed
    weak = confidence.score(["page-reference"], "changelog-anchor", "assumed")
    assert confidence.tier_for(weak) == "ASSUMED"

    assert confidence.MIN_SCORE <= weak < high <= confidence.MAX_SCORE


def test_resolve_core_corroboration_and_discrepancy():
    agreeing = [("6.4.3", "meta-generator", "meta generator tag"),
                ("6.4.3", "rss-generator", "RSS feed")]
    resolved = confidence.resolve_core(agreeing)
    assert resolved["version"] == "6.4.3" and resolved["discrepancy"] is False
    # 62 + 12 corroboration = 74: single-tier-below-CONFIRMED agreement
    assert resolved["score"] == 74 and confidence.tier_for(74) == "LIKELY"

    disagreeing = [("6.4.3", "meta-generator", "meta generator tag"),
                   ("6.7.1", "readme-html", "readme.html")]
    resolved = confidence.resolve_core(disagreeing)
    assert resolved["version"] == "6.4.3"     # priority order wins
    assert resolved["discrepancy"] is True    # ...but flagged and demoted
    assert confidence.tier_for(resolved["score"]) == "UNVERIFIED"
    assert "6.7.1" in resolved["values"]

    assert confidence.resolve_core([]) is None


def test_scan_model_json_graph(tmp_path):
    """The knowledge-graph export: nodes for components/vulns, edges for
    'site runs component' / 'component affected-by vulnerability'."""
    model = confidence.ScanModel()
    cid = model.add_component("plugin", "demo", "1.0", "stable-tag",
                              ["readme-200", "page-reference"],
                              conf={"score": 97, "tier": "CONFIRMED"})
    model.add_component("plugin", "demo", presence=["fingerprint"])  # merges evidence
    vid = model.add_vulnerability(cid, {"name": "CVE-X", "severity": "7.5 (high)",
                                        "link": "https://example", "basis": "bounded"},
                                  conf={"score": 90})

    path = tmp_path / "graph.json"
    model.write_json(path, "https://site.example.com/")
    data = json.loads(path.read_text(encoding="utf-8"))

    assert data["target"] == "https://site.example.com/"
    nodes = {n["id"]: n for n in data["nodes"]}
    assert nodes[cid]["version"] == "1.0"
    assert {"readme-200", "page-reference", "fingerprint"} <= set(nodes[cid]["presence"])
    assert nodes[cid]["confidence"]["tier"] == "CONFIRMED"
    assert nodes[vid]["applicability"] == "bounded"

    relations = {(e["from"], e["to"], e["relation"]) for e in data["edges"]}
    assert ("site", cid, "runs") in relations
    assert (cid, vid, "affected-by") in relations


def test_versioning():
    assert versioning.compare_versions("6.4", "6.4.0") == 0
    assert versioning.compare_versions("5.10", "5.9") == 1
    assert versioning.compare_versions("6.4.3", "6.4.10") == -1
    assert versioning.major_minor("6.4.3") == "6.4"
    assert versioning.extract_version("WordPress 6.4.3 ready") == "6.4.3"
    assert versioning.extract_version("no numbers here") is None


# ---------------------------------------------------------------- code audit

def test_analyzer_rules_and_exclusions(tmp_path):
    tmp_path.joinpath("safe.php").write_text(
        '<?php\n'
        '$id = $wpdb->get_var($wpdb->prepare("SELECT id FROM p WHERE id = %d", $_GET["x"]));\n'
        '$wpdb->query("UPDATE p SET a = 1");\n'
    )
    tmp_path.joinpath("evil.php").write_text(
        '<?php\n'
        'eval(base64_decode($_POST["cmd"]));\n'
        'unserialize($_REQUEST["payload"]);\n'
        '$wpdb->get_results("SELECT * FROM p WHERE id = " . $_GET["id"]);\n'
        'include($_GET["page"]);\n'
        'echo $_POST["msg"];\n'
        'system("ls " . $_GET["d"]);\n'
    )
    findings = analyzer.analyze(tmp_path)
    rules = {f["rule"] for f in findings}

    assert "backdoor-obfuscation" in rules
    assert "request-unserialize" in rules
    assert "sqli-request" in rules
    assert "file-inclusion" in rules
    assert "xss-echo" in rules
    assert "command-exec" in rules
    # the prepare() line must NOT be flagged
    assert not any(f["file"] == "safe.php" and f["rule"].startswith("sqli") for f in findings)


def test_analyzer_string_literal_false_positives(tmp_path):
    """The LiteSpeed bug: a minifier's 'exec(' token list is NOT a call."""
    tmp_path.joinpath("tokens.php").write_text(
        '<?php\n'
        "$preserve = array('exec(', 'system(', 'passthru(');\n"  # string literals
    )
    findings = analyzer.analyze(tmp_path)
    assert not any(f["rule"] == "command-exec" for f in findings)

    tmp_path.joinpath("real.php").write_text('<?php\nexec("id");\n')
    assert any(f["rule"] == "command-exec" for f in analyzer.analyze(tmp_path))


def test_analyzer_skips_class_files_for_csrf(tmp_path):
    """Trait/class files are included by WP, never routed: no csrf heuristic."""
    tmp_path.joinpath("handler.trait.php").write_text(
        '<?php\ntrait Cloud {\n  function save() { $x = $_POST["hash"]; } }\n')
    tmp_path.joinpath("endpoint.php").write_text(
        '<?php\n$x = $_POST["action"];\necho "done";\n')
    findings = analyzer.analyze(tmp_path)
    assert not any(f["rule"] == "csrf-no-nonce" and "trait" in f["file"] for f in findings)
    assert any(f["rule"] == "csrf-no-nonce" and f["file"] == "endpoint.php" for f in findings)


def test_analyzer_include_demoted_without_request_input(tmp_path):
    """Plain `include $file` (autoloader pattern) is LOW, not a HIGH LFI."""
    tmp_path.joinpath("auto.php").write_text('<?php\ninclude $cls_file;\n')
    inc = [f for f in analyzer.analyze(tmp_path) if f["rule"].startswith("include")
           or f["rule"].startswith("file")]
    assert inc and inc[0]["severity"] == "LOW" and inc[0]["rule"] == "include-variable"


def test_analyzer_ajax_missing_auth_rule(tmp_path):
    """The Claude+Semgrep join rule: wp_ajax registrations whose callback body
    lacks a capability/nonce check. nopriv = unauthenticated (HIGH)."""
    tmp_path.joinpath("ajax.php").write_text(
        '<?php\n'
        "add_action('wp_ajax_nopriv_export_data', 'export_data');\n"
        "function export_data() { echo file_get_contents($_GET['file']); }\n"
        "add_action('wp_ajax_admin_tool', 'admin_tool_checked');\n"
        "function admin_tool_checked() {\n"
        "    if (!current_user_can('manage_options')) { wp_die('no'); }\n"
        "    delete_option($_POST['opt']);\n"
        "}\n"
        "add_action('wp_ajax_subthing', 'subthing');\n"
        "function subthing() { update_option('x', $_POST['v']); }\n"
        "add_action('wp_ajax_ignored', array($this, 'method'));\n"  # array callback: skipped
    )
    ajax = [f for f in analyzer.analyze(tmp_path) if f["rule"] == "ajax-handler-no-auth"]
    unauth = [f for f in ajax if "nopriv" in f["snippet"]]
    assert len(unauth) == 1 and unauth[0]["severity"] == "HIGH"
    sub = [f for f in ajax if "subthing" in f["snippet"]]
    assert len(sub) == 1 and sub[0]["severity"] == "MEDIUM"
    # the capability-checked callback is NOT flagged; array callbacks skipped
    assert not any("admin_tool_checked" in f["snippet"] or "ignored" in f["snippet"]
                   for f in ajax)


def test_analyzer_is_admin_is_not_authorization(tmp_path):
    """is_admin() checks request context, not user capabilities - hiding
    behind it must still be flagged (documented WP gotcha)."""
    tmp_path.joinpath("fake.php").write_text(
        '<?php\n'
        "add_action('wp_ajax_nopriv_leak', 'leak_it');\n"
        "function leak_it() { if (is_admin()) { echo get_option('secret'); } }\n"
    )
    hits = [f for f in analyzer.analyze(tmp_path) if f["rule"] == "ajax-handler-no-auth"]
    assert hits and hits[0]["severity"] == "HIGH"


def test_analyzer_ajax_rule_follows_one_hop_delegation(tmp_path):
    """The real Yoast pattern: thin wp_ajax wrappers delegate to a helper
    that DOES check_ajax_referer - not a finding (once tripped the rule)."""
    tmp_path.joinpath("yoast.php").write_text(
        '<?php\n'
        "add_action('wp_ajax_wpseo_save_title', 'wpseo_save_title');\n"
        "function wpseo_save_title() {\n"
        "    _deprecated_function(__FUNCTION__, 'Yoast SEO 28.1');\n"
        "    wpseo_save_what('title');\n"
        "}\n"
        "function wpseo_save_what($what) {\n"
        "    check_ajax_referer('wpseo-bulk-editor');\n"
        "    if (!current_user_can('edit_posts')) { wp_die('no'); }\n"
        "}\n"
    )
    hits = [f for f in analyzer.analyze(tmp_path) if f["rule"] == "ajax-handler-no-auth"]
    assert hits == []

    # same shape but the helper has NO check either -> still a finding
    tmp_path.joinpath("bad.php").write_text(
        '<?php\n'
        "add_action('wp_ajax_nopriv_export', 'export_it');\n"
        "function export_it() { do_export(); }\n"
        "function do_export() { echo file_get_contents($_GET['f']); }\n"
    )
    hits = [f for f in analyzer.analyze(tmp_path) if f["rule"] == "ajax-handler-no-auth"]
    assert hits and hits[0]["severity"] == "HIGH"


def test_analyzer_ajax_rule_accepts_nonce_wrappers(tmp_path):
    """Framework nonce wrappers (WPSEO_Utils::verify_nonce, $this->verify_nonce)
    satisfy the authorization requirement."""
    tmp_path.joinpath("wrapped.php").write_text(
        '<?php\n'
        "add_action('wp_ajax_save_thing', 'save_thing');\n"
        "function save_thing() { WPSEO_Utils::verify_nonce(); update_option('x', 1); }\n"
    )
    hits = [f for f in analyzer.analyze(tmp_path) if f["rule"] == "ajax-handler-no-auth"]
    assert hits == []


def test_analyzer_csrf_skips_psr4_class_files(tmp_path):
    """Yoast-style PSR-4 conditionals are autoloaded class definitions, never
    routed directly - csrf-no-nonce must not fire on them."""
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "conditional.php").write_text(
        '<?php\n'
        "namespace Yoast\\WP\\SEO\\Conditionals;\n"
        "class Estimated_Reading_Time_Conditional implements Conditional {\n"
        "\tpublic function is_met() { return isset($_POST['x']); }\n"
        "}\n"
    )
    csrf = [f for f in analyzer.analyze(tmp_path) if f["rule"] == "csrf-no-nonce"]
    assert csrf == []

    # a genuinely routed procedural file still gets the heuristic
    tmp_path.joinpath("routed.php").write_text(
        '<?php add_action("admin_post_save", "save"); function save() { echo $_POST["d"]; }\n'
    )
    csrf = [f for f in analyzer.analyze(tmp_path) if f["rule"] == "csrf-no-nonce"]
    assert csrf and csrf[0]["file"] == "routed.php"


def test_analyzer_demotes_bundled_vendor_code(tmp_path):
    """eval() inside vendor_prefixed/twig is bundled framework code - real,
    but one severity step down and labelled, not billed as the plugin's own."""
    vendor = tmp_path / "vendor_prefixed" / "twig"
    vendor.mkdir(parents=True)
    vendor.joinpath("environment.php").write_text(
        '<?php eval("?> " . $content);\n'
    )
    hits = analyzer.analyze(tmp_path)
    evals = [f for f in hits if f["rule"] == "eval-usage"]
    assert evals and evals[0]["severity"] == "MEDIUM"   # HIGH demoted one step
    assert "bundled vendor/test code" in evals[0]["description"]

    # the plugin author's own eval stays HIGH, unlabelled
    tmp_path.joinpath("own.php").write_text('<?php eval($x . "!");\n')
    own = [f for f in analyzer.analyze(tmp_path)
           if f["rule"] == "eval-usage" and f["file"] == "own.php"]
    assert own and own[0]["severity"] == "HIGH"


def test_divi_changelog_version():
    """Changelogs are newest-first: the head version wins (Divi 4.27.7, not 4.16)."""
    changelog = (
        "version 4.27.7 ( updated 05-12-2026 ) | - Security Update: Fixed a stored XSS "
        "risk in Social Media Follow Skype URL handling\n"
        "version 4.16 ( updated 03-15-2022 ) | - Added features and improvements\n"
    )
    assert readme._version_from_readme(changelog) == ("4.27.7", "stable-tag")


def test_safe_extract_blocks_zip_slip(tmp_path):
    malicious = tmp_path / "malicious.zip"
    with zipfile.ZipFile(malicious, "w") as zf:
        zf.writestr("../../escaped.txt", "pwned")
    with pytest.raises(zipfile.BadZipFile):
        safe_extract_zip(malicious, tmp_path / "out")
    assert not (tmp_path.parent.parent / "escaped.txt").exists()


def test_gather_from_target_listing(mock, tmp_path):
    listing = f"{mock}wp-content/plugins/vulnplugin/"
    dest = tmp_path / "mirror"
    result = gather.gather_from_target(listing, dest)
    assert result is not None
    mirrored = [p.name for p in dest.rglob("*") if p.is_file()]
    assert "vulnplugin.php" in mirrored
    assert "shell.php" in mirrored  # nested via inc/ sub-listing


# ------------------------------------------------------- multi-method gathering

def _plugin_zip_bytes(slug, version):
    """A minimal plugin archive: {slug}/{slug}.php header + readme Stable tag."""
    import io as _io
    buffer = _io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as zf:
        zf.writestr(f"{slug}/{slug}.php",
                    f"<?php\n/**\n * Plugin Name: {slug}\n * Version: {version}\n */\n")
        zf.writestr(f"{slug}/readme.txt", f"=== {slug} ===\nStable tag: {version}\n")
    return buffer.getvalue()


def test_gather_prefers_operator_zip(tmp_path):
    """A licensed copy in --source-dir wins over every download method, and
    the archive's self-reported version is verified."""
    src = tmp_path / "sources"
    src.mkdir()
    (src / "plugin-demo-1.2.3.zip").write_bytes(_plugin_zip_bytes("demo", "1.2.3"))
    dest = tmp_path / "out"
    source, origin, reason = gather.gather_from_wordpress(
        "plugin", "demo", "1.2.3", dest, source_dir=src)
    assert source == dest and reason is None
    assert "operator-provided" in origin and "WARNING" not in origin
    assert (dest / "demo" / "demo.php").exists()


def test_gather_flags_operator_zip_version_mismatch(tmp_path):
    """Right file name, wrong contents: audited, but the origin says so."""
    src = tmp_path / "sources"
    src.mkdir()
    (src / "plugin-demo-1.2.3.zip").write_bytes(_plugin_zip_bytes("demo", "1.0.0"))
    source, origin, reason = gather.gather_from_wordpress(
        "plugin", "demo", "1.2.3", tmp_path / "out", source_dir=src)
    assert source is not None
    assert "self-reports 1.0.0, expected 1.2.3" in origin


def test_gather_api_version_map_resolution(monkeypatch, tmp_path):
    """The wordpress.org API versions map wins over URL guessing, with
    zero-padding normalization ('2.0' matches published '2.0.0')."""
    payload = {"slug": "demo", "versions": {
        "1.9.0": "https://downloads.wordpress.org/plugin/demo.1.9.0.zip",
        "2.0.0": "https://downloads.wordpress.org/plugin/demo.2.0.0.zip"}}
    monkeypatch.setattr(httpclient, "get_json",
                        lambda url, **kw: payload if "api.wordpress.org" in url else None)

    def fake_get(url, **kw):
        assert "demo.2.0.0.zip" in url          # the API's exact link, not a guess
        resp = FakeResp(200, "zip")
        resp.content = _plugin_zip_bytes("demo", "2.0.0")
        return resp

    monkeypatch.setattr(httpclient, "get", fake_get)
    source, origin, reason = gather.gather_from_wordpress(
        "plugin", "demo", "2.0", tmp_path / "out")
    assert source is not None and "matched published 2.0.0" in origin


def test_gather_reports_why_it_failed(monkeypatch, tmp_path):
    """Failures carry a machine reason the report can explain honestly."""
    def server(api_payload):
        monkeypatch.setattr(httpclient, "get_json",
                            lambda url, **kw: api_payload if "api.wordpress.org" in url else None)
        monkeypatch.setattr(httpclient, "get", lambda url, **kw: None)
        return gather.gather_from_wordpress("plugin", "demo", "1.0", tmp_path / "out")

    assert server({"error": "not found"})[2] == "not-hosted"
    assert server({"slug": "demo", "versions": {"9.9.9": "x"}})[2] == "version-not-published"
    assert server(None)[2] == "download-failed"
    assert gather.gather_from_wordpress("plugin", "demo", None, tmp_path / "o")[2] == "no-version"


# ---------------------------------------------------------------- slug enumeration

def test_enum_plugins(mock):
    from wpbuddy.active import enumerate as slug_enum
    report = Report()
    slugs = ["woocommerce", "akismet", "definitely-not-here"]
    installed = slug_enum.enumerate_plugins(report, mock, slugs)
    assert installed == ["woocommerce"]  # only woocommerce ships a readme.txt on the mock
    assert "woocommerce" in report.doc.write()


def test_enum_blanket_deny_no_false_positives(monkeypatch):
    """A WAF 403ing the whole plugins-readme class must not make every slug 'installed'."""
    from wpbuddy import httpclient
    from wpbuddy.active import enumerate as slug_enum

    # bogus-slug probe, real slugs and every obfuscation variant: all 403
    monkeypatch.setattr(httpclient, "get", lambda url, **kw: FakeResp(403))
    report = Report()
    installed = slug_enum.enumerate_plugins(report, "https://site.example.com/",
                                            ["woocommerce", "akismet", "x"])
    assert installed == []
    assert "blanket firewall rule" in report.doc.write()


# ---------------------------------------------------------------- PoC generation

def test_poc_verified_live(mock):
    """A directly-accessible reflected-output file is reproduced with a benign marker.

    The analyzer runs over the fixture source (the mock 'executes' reflect.php,
    so its source can't be mirrored - realistic); the PoC is then verified live
    against the executing endpoint.
    """
    fixtures = Path(__file__).parent / "fixtures" / "mockwp"
    findings = analyzer.analyze(fixtures)

    target_findings = [f for f in findings
                       if f["rule"] == "xss-echo" and f["file"].endswith("reflect.php")]
    assert target_findings and target_findings[0]["params"] == ["msg"]

    finding = target_findings[0]
    url = poc.url_for_finding(finding, mock, "plugin", mirrored=True)
    assert url.endswith("/wp-content/plugins/vulnplugin/reflect.php")
    result = poc.try_verify(finding, url)
    assert result and result["verified"] is True
    assert result["poc"]["url"].endswith("/wp-content/plugins/vulnplugin/reflect.php")


def test_poc_template_for_manual_rules():
    finding = {"rule": "command-exec", "params": ["dir"], "file": "x/y.php",
               "line": 1, "snippet": "system('ls ' . $_GET['dir']);"}
    built = poc.build_poc(finding, "http://t/wp-content/plugins/x/y.php")
    cmd = poc.render_curl(built)
    assert cmd.startswith("curl")
    # shell-quoting must survive payloads containing quotes (old output broke here)
    import shlex
    assert len(shlex.split(cmd)) >= 4

    raw = poc.render_raw_http(built)
    assert raw.startswith("GET /wp-content/plugins/x/y.php")
    assert "Host: t" in raw and "User-Agent:" in raw


def test_poc_raw_request_post_body():
    finding = {"rule": "request-unserialize", "params": ["payload"], "file": "s.php",
               "line": 3, "snippet": "unserialize($_REQUEST['payload']);"}
    built = poc.build_poc(finding, "https://victim.example.com/wp-content/plugins/p/s.php")
    raw = poc.render_raw_http(built)
    assert raw.startswith("POST /wp-content/plugins/p/s.php")
    assert "Host: victim.example.com" in raw
    assert "Content-Type: application/x-www-form-urlencoded" in raw
    assert "payload=" in raw


def test_poc_pack_written(tmp_path):
    finding = {"rule": "command-exec", "params": ["dir"], "file": "wp-content/plugins/x/y.php",
               "line": 9, "severity": "HIGH", "snippet": "system($_GET['dir']);",
               "description": "OS command execution function"}
    built = poc.build_poc(finding, "http://t/wp-content/plugins/x/y.php")
    files = poc.write_pack(tmp_path / "pocs", [("plugin x", finding, built)])
    assert len(files) == 1
    text = files[0].read_text()
    assert files[0].name.startswith("POC-001_command-exec")
    assert "plugin x" in text and "wp-content/plugins/x/y.php:9" in text
    assert "GET /wp-content/plugins/x/y.php?dir=" in text  # raw request present


# ---------------------------------------------------------------- access assessment

def test_open_registration_detected(mock):
    report = Report()
    assert access.check_open_registration(report, mock) is True
    assert "Self-registration is ENABLED" in report.doc.write()


def test_login_error_differential(mock):
    report = Report()
    valid = access.validate_usernames(report, mock, ["admin", "ghost-user-xyz"])
    assert valid == ["admin"]  # mock confirms 'admin', rejects the ghost


def test_password_spray_wplogin(mock):
    report = Report()
    found = access.password_spray(report, mock, ["admin", "adminsite"],
                                  ["Welcome1", "dadadada", "Password1"])
    assert found == {"admin": "dadadada"}


def test_password_spray_xmlrpc_single_request(mock):
    """One spray round through system.multicall = one HTTP request for all users."""
    found = access.password_spray(Report(), mock, ["admin", "adminsite"],
                                  ["Welcome1", "dadadada"], via_xmlrpc=True)
    assert found == {"admin": "dadadada"}


def test_password_spray_stops_when_login_unreachable(monkeypatch):
    """A dead/blocked wp-login must end the spray, not grind every user x round."""
    calls = []
    monkeypatch.setattr(access, "_login_post",
                        lambda *a, **kw: (calls.append(a), None)[1])
    found = access.password_spray(Report(), "https://site.example.com/",
                                  ["admin", "editor"], ["p1", "p2", "p3"])
    assert found == {}
    assert len(calls) == 1   # first user, first round - then it stopped


def test_password_spray_xmlrpc_stops_on_transport_failure(monkeypatch):
    calls = []
    monkeypatch.setattr(httpclient, "post",
                        lambda url, **kw: (calls.append(url), None)[1])
    found = access.password_spray(Report(), "https://site.example.com/",
                                  ["admin"], ["p1", "p2"], via_xmlrpc=True)
    assert found == {}
    assert len(calls) == 1   # one failed multicall ends the attack


# ---------------------------------------------------------------- full CLI run

def test_cli_end_to_end(mock, tmp_path, monkeypatch):
    """Full pipeline against the mock site with the vuln DB stubbed offline."""
    def fake_fetch(kind, slug):
        if kind == "core":
            return {"core": slug, "vulnerability": [
                {"operator": {"max_version": "99.0", "max_operator": "lt"},
                 "source": [{"name": "CVE-2020-11111", "description": "core issue"}]},
                {"operator": {"max_version": "99.0", "max_operator": "lt"},
                 "source": [{"name": "DUP-CVE-2020-11111", "description": "core issue"}]},
            ]}
        if kind == "plugin" and slug == "contact-form-7":
            return {"plugin": slug, "vulnerability": [
                {"operator": {"max_version": "5.3.2", "max_operator": "lt"},
                 "source": [{"name": "CVE-2020-35489", "description": "unrestricted file upload"}]},
            ]}
        if kind == "theme" and slug == "twentytwentythree":
            return {"theme": slug, "vulnerability": None}
        return None  # unknown slug -> API data is null (the old crash case)

    monkeypatch.setattr(vulndb, "_fetch", fake_fetch)
    # keep wordpress.org downloads out of the offline test
    monkeypatch.setattr(gather, "gather_from_wordpress", lambda *a, **k: None)
    monkeypatch.chdir(tmp_path)

    from wpbuddy import cli

    output = tmp_path / "report"
    with pytest.raises(SystemExit) as exc:
        cli.main(["--target", mock,
                  "--pluginList", str(Path(__file__).parent / "fixtures" / "testPlugins.txt"),
                  "--user", VALID_USER,
                  "--passwordList", str(Path(__file__).parent.parent / "data" / "numeparola.txt"),
                  "--output", str(output), "--audit-code", "target", "--json"])
    assert exc.value.code == 0

    text = output.with_suffix(".md").read_text(encoding="utf-8")
    assert "6.4.3" in text                    # core version
    assert "CVE-2020-11111" in text           # core vuln
    assert len(text.split("core issue")) == 2  # duplicate description deduplicated to one bullet
    assert "CVE-2020-35489" in text           # plugin vuln matched by version
    assert "contact-form-7/v1" in text        # REST namespace fingerprint
    assert "debug.log" in text                # sensitive file
    assert "adminsite" in text                # user enumeration
    assert "dadadada" in text                 # cracked credentials
    assert "backdoor-obfuscation" in text     # code audit finding via listing mirror
    assert "system.multicall" in text         # xmlrpc report
    assert "[CONFIRMED]" in text              # confidence tiers are rendered
    assert "version range matched" in text    # advisory basis rendered with findings

    graph = json.loads(output.with_suffix(".json").read_text(encoding="utf-8"))
    nodes = {n["id"]: n for n in graph["nodes"]}
    assert nodes["core:wordpress"]["version"] == "6.4.3"
    cf7 = nodes["plugin:contact-form-7"]
    assert cf7["version"] == "5.3.1" and cf7["version_source"] == "stable-tag"
    assert "fingerprint" in cf7["presence"]   # REST namespace counted as evidence
    assert cf7["confidence"]["tier"] == "CONFIRMED"
    relations = {(e["from"], e["to"], e["relation"]) for e in graph["edges"]}
    assert ("site", "plugin:contact-form-7", "runs") in relations
    assert any(to.startswith("vuln:plugin:contact-form-7:")
               for _, to, rel in relations if rel == "affected-by")


# ------------------------------------------------------------- CLI target handling (P0-1)

def record_sent_urls(monkeypatch):
    """Sent-URL recorder: wrap the HTTP layer and record every requested URL."""
    sent = []
    real_request = httpclient.request

    def recording_request(method, url, **kwargs):
        sent.append(url)
        return real_request(method, url, **kwargs)

    monkeypatch.setattr(httpclient, "request", recording_request)
    return sent


def test_normalize_target_strips_query_and_fragment():
    """A query/fragment on --target must not leak into subsequent probe paths."""
    from wpbuddy import cli
    url, error = cli._normalize_target("https://example.com/?utm=x#top")
    assert error is None
    assert url == "https://example.com/"
    assert cli._normalize_target("https://x/?utm=1")[0] == "https://x/"      # no double slash
    assert cli._normalize_target("https://x/blog")[0] == "https://x/blog/"  # path is kept
    assert cli._normalize_target("https://x/blog/?utm=1")[0] == "https://x/blog/"
    assert cli._normalize_target("  https://x/  ")[0] == "https://x/"       # stripped
    assert cli._normalize_target("example.com")[0] is None                  # no scheme
    assert cli._normalize_target("ftp://x/")[0] is None
    assert cli._normalize_target("https:///?q=1")[0] is None                # empty hostname


def test_cli_target_with_query_and_fragment_reaches_paths(mock, tmp_path, monkeypatch):
    """`--target <mock>/?utm=x#top` must reach /robots.txt, /wp-json/ and
    /xmlrpc.php on the site root, not push every path into the query string."""
    sent = record_sent_urls(monkeypatch)
    monkeypatch.setattr(vulndb, "_fetch", lambda kind, slug: None)  # offline DB
    from wpbuddy import cli

    output = tmp_path / "report"
    with pytest.raises(SystemExit) as exc:
        cli.main(["--target", mock + "?utm=x&utm2=y#top",
                  "--pluginList", "",
                  "--audit-code", "off",
                  "--output", str(output)])
    assert exc.value.code == 0

    assert f"{mock}robots.txt" in sent
    assert f"{mock}wp-json/" in sent
    assert f"{mock}xmlrpc.php" in sent
    assert all("utm" not in u and "#" not in u for u in sent), "query/fragment leaked into probes"


# ------------------------------------------------------------- stealth contract (P0-2)

def test_cli_stealth_never_probes_target_listings(mock, tmp_path, monkeypatch):
    """--stealth says 'passive phase only': after the passive requests, the
    code audit must not probe /wp-content/plugins/<slug>/ listings."""
    sent = record_sent_urls(monkeypatch)
    monkeypatch.setattr(vulndb, "_fetch", lambda kind, slug: None)  # offline DB
    monkeypatch.setattr(gather, "gather_from_wordpress",
                        lambda *a, **k: (None, None, "not-hosted"))  # offline audit
    from wpbuddy import cli

    output = tmp_path / "report"
    with pytest.raises(SystemExit) as exc:
        cli.main(["--target", mock, "--pluginList", "", "--stealth",
                  "--output", str(output)])
    assert exc.value.code == 0

    listings = [u for u in sent if re.search(r"wp-content/(plugins|themes)/[^/]+/$", u)]
    assert listings == [], f"stealth scan probed target listings: {listings}"


def test_cli_stealth_with_explicit_audit_target_warns(mock, tmp_path, monkeypatch, capsys):
    """An explicit --audit-code target|auto with --stealth gets a warning that
    target requests will still happen."""
    monkeypatch.setattr(vulndb, "_fetch", lambda kind, slug: None)
    from wpbuddy import cli

    output = tmp_path / "report"
    with pytest.raises(SystemExit) as exc:
        cli.main(["--target", mock, "--pluginList", "", "--stealth",
                  "--audit-code", "target", "--output", str(output)])
    assert exc.value.code == 0
    out = capsys.readouterr().out
    assert "--audit-code target" in out
    assert "target requests" in out.lower() or "reach" in out.lower()


# ------------------------------------------------------------- audit cache semantics (P0-3)

def _mirror_vuln_cache(root, host, marker=True):
    """Cache layout a previous scan left after mirroring plugin 'vuln' 1.0."""
    php = root / "wpbuddy-audit" / host / "plugin-vuln-1.0" / "target" / \
        "wp-content" / "plugins" / "vuln" / "vuln.php"
    php.parent.mkdir(parents=True)
    php.write_text('<?php\neval(base64_decode($_REQUEST["cmd"]));\n')
    if marker:
        (root / "wpbuddy-audit" / host / "plugin-vuln-1.0" / ".origin").write_text("mirrored\n")
    return php


def test_cached_mirror_keeps_mirror_semantics(mock, tmp_path, monkeypatch):
    """A cached mirror is analyzed from its target/ subtree: finding paths
    start at wp-content/ and PoC URLs carry no double prefix (the old code
    walked the cache root, producing .../plugins/target/wp-content/plugins/...)."""
    from types import SimpleNamespace as NS
    from urllib.parse import urlsplit
    from wpbuddy import codeaudit

    monkeypatch.chdir(tmp_path)
    host = urlsplit(mock).hostname
    _mirror_vuln_cache(tmp_path, host, marker=True)
    monkeypatch.setattr(httpclient, "get", lambda url, **kw: FakeResp(404, "offline"))

    args = NS(audit_code="target", verify_pocs=True, source_dir=None)
    findings = codeaudit.run(Report(), mock, {"plugins": {"vuln": "1.0"}}, args)["vuln"]
    assert findings
    assert all(f["file"].startswith("wp-content/") for f in findings)
    poc_urls = [f["poc"]["poc"]["url"] for f in findings if f.get("poc")]
    assert poc_urls
    assert all(u == f"{mock}wp-content/plugins/vuln/vuln.php" for u in poc_urls)


def test_cached_mirror_inferred_without_marker(mock, tmp_path, monkeypatch):
    """Marker-less legacy caches with a target/ subtree are still mirrors."""
    from types import SimpleNamespace as NS
    from urllib.parse import urlsplit
    from wpbuddy import codeaudit

    monkeypatch.chdir(tmp_path)
    _mirror_vuln_cache(tmp_path, urlsplit(mock).hostname, marker=False)
    monkeypatch.setattr(httpclient, "get", lambda url, **kw: FakeResp(404, "offline"))

    args = NS(audit_code="target", verify_pocs=False, source_dir=None)
    findings = codeaudit.run(Report(), mock, {"plugins": {"vuln": "1.0"}}, args)["vuln"]
    assert findings and findings[0]["file"].startswith("wp-content/")


# ------------------------------------------------------------- DB reachability honesty (P0-4)

def test_lookup_statuses_distinguish_failure_from_clean(monkeypatch):
    """'unreachable' (transport failed) vs 'not-found' (API answered: unknown
    slug) vs 'ok' with an empty list (known and clean)."""
    monkeypatch.setattr(vulndb, "_fetch", lambda kind, slug: None)  # outage
    assert vulndb.core_lookup("6.4") == (None, "unreachable")
    assert vulndb.plugin_lookup("x") == (None, "unreachable")
    assert vulndb.theme_lookup("x") == (None, "unreachable")

    monkeypatch.setattr(vulndb, "_fetch", lambda kind, slug: (None, "not-found"))
    assert vulndb.plugin_lookup("unknown-slug") == (None, "not-found")

    monkeypatch.setattr(vulndb, "_fetch",
                        lambda kind, slug: ({"vulnerability": None}, "ok"))
    vulns, status = vulndb.plugin_lookup("clean-slug")
    assert status == "ok" and vulns == []


def test_core_report_failure_vs_clean(monkeypatch):
    """An API outage must read as 'lookup failed', never as
    'No known vulnerabilities'."""
    from wpbuddy import passive
    monkeypatch.setattr(passive.core_version, "discover_core_version",
                        lambda target: [("6.4.3", "meta-generator", "meta generator tag")])
    monkeypatch.setattr(vulndb, "_fetch", lambda kind, slug: None)

    report = Report()
    passive._scan_core(report, "https://x.example.com/", confidence.ScanModel())
    text = report.doc.write()
    assert "unreachable" in text and "lookup failed" in text
    assert "No known vulnerabilities" not in text

    # the API answering 'vulnerability: null' IS a clean result
    monkeypatch.setattr(vulndb, "_fetch",
                        lambda kind, slug: ({"vulnerability": None}, "ok"))
    report = Report()
    passive._scan_core(report, "https://x.example.com/", confidence.ScanModel())
    text = report.doc.write()
    assert "No known vulnerabilities" in text


def test_plugin_report_failure_not_clean(monkeypatch):
    from wpbuddy import passive
    args = SimpleNamespace(pluginList=None, enum_plugins=False, max_pages=1)
    monkeypatch.setattr(passive.fingerprints, "detect", lambda artifacts, ns: set())
    monkeypatch.setattr(passive.readme, "find_component_version",
                        lambda target, kind, slug: ("1.0", "readme.txt", "stable-tag"))
    monkeypatch.setattr(vulndb, "_fetch", lambda kind, slug: None)

    report = Report()
    passive._scan_plugins(report, "https://x.example.com/", args, [],
                          confidence.ScanModel(), ["https://x.example.com/"],
                          {"plugins": {"someplugin"}, "themes": set()},
                          {"pages_html": "", "cookies": set(), "headers": []})
    text = report.doc.write()
    assert "unreachable" in text
    assert "not present in the vulnerability database" not in text


def test_analyzer_preg_e_modifier_single_quoted(tmp_path):
    """The /e modifier sits inside a single-quoted pattern, which code_view
    blanks - the rule must still fire (P0-6), without loosening the
    string-literal controls for other rules."""

    def scan(name, code):
        case = tmp_path / name
        case.mkdir()
        (case / "case.php").write_text(code)
        return analyzer.analyze(case)

    findings = scan("e", '<?php\necho preg_replace(\'/foo/e\', \'$1\', $y);\n')
    assert any(f["rule"] == "preg-e-modifier" and f["severity"] == "HIGH" for f in findings)

    # same pattern without /e is not a finding
    assert not any(f["rule"] == "preg-e-modifier"
                   for f in scan("noe", '<?php\necho preg_replace(\'/foo/\', \'b\', $y);\n'))

    # 'e' merely appearing in the pattern ('/red/') is not an /e modifier
    assert not any(f["rule"] == "preg-e-modifier"
                   for f in scan("red", '<?php\necho preg_replace(\'/red/\', \'b\', $y);\n'))

    # the double-quoted case keeps working (through the raw view now)
    assert any(f["rule"] == "preg-e-modifier"
               for f in scan("dq", '<?php\necho preg_replace("/foo/e", "$1", $y);\n'))

    # minifier token lists of the rule text itself are still not calls
    assert not any(f["rule"] == "preg-e-modifier"
                   for f in scan("tokens", '<?php\n$preserve = array(\'preg_replace(\', \'/e/\');\n'))


# ------------------------------------------------------------- same-site collectors (P0-7)

def test_waf_and_errorpages_accept_same_site_hosts(monkeypatch):
    """A site scanned at example.com but served from www.example.com must
    still get WAF detection and error-page collection; third-party API
    hosts must stay ignored."""
    from wpbuddy import config, waf
    from wpbuddy.passive import errorpages
    waf.reset()
    errorpages.reset()
    monkeypatch.setattr(config, "TARGET_HOST", "example.com")

    fatal = ("<html><body>Fatal error: call in "
             "/home/u/public_html/wp-content/plugins/foo/x.php on line 3</body></html>")
    resp = FakeResp(200, fatal, url="https://www.example.com/x")
    resp.headers = {"Server": "cloudflare", "Cf-Ray": "abc123"}
    waf.inspect_response(resp)
    errorpages.inspect(resp)
    assert "Cloudflare" in waf.detected()
    assert len(errorpages.entries()) == 1

    sub = FakeResp(500, fatal, url="https://static.example.com/y")
    sub.headers = {"Server": "cloudflare"}
    waf.inspect_response(sub)
    errorpages.inspect(sub)
    assert len(errorpages.entries()) == 2   # own CDN subdomain counts too

    # third-party API hosts are still ignored
    api = FakeResp(200, fatal, url="https://api.wordpress.org/x")
    api.headers = {"Server": "cloudflare"}
    waf.inspect_response(api)
    errorpages.inspect(api)
    assert len(errorpages.entries()) == 2
    waf.reset()
    errorpages.reset()


def test_advisory_bounds_promote_assumed_to_bounded():
    """An 'assumed' finding whose advisory bounds DO include the installed
    version becomes 'bounded' - dozens of clearly-range-matched findings
    used to render as [ASSUMED] (P1-1). Only 'assumed' is promoted;
    'unfixed' advisories keep their explicit claim."""
    inside = [{"operator": {},
               "source": [{"name": "WordPress <= 6.9.1 - stored XSS", "description": "xss"}]}]
    assert vulndb.affected_vulnerabilities("6.6.8", inside)[0]["basis"] == "bounded"

    below = [{"operator": {},
              "source": [{"name": "WordPress <= 6.5.0 - stored XSS", "description": "xss"}]}]
    assert vulndb.affected_vulnerabilities("6.6.8", below)[0]["basis"] == "contradicted"

    multi = [{"operator": {},
              "source": [{"name": "Affects 6.0 through 6.2 and 6.6 through 6.9.1",
                          "description": "d"}]}]
    assert vulndb.affected_vulnerabilities("6.6.8", multi)[0]["basis"] == "bounded"


def test_cli_rejects_bad_target():
    from wpbuddy import cli
    with pytest.raises(SystemExit) as exc:
        cli.main(["--target", "example.com"])
    assert exc.value.code == 1


# ---------------------------------------------------------------- covert traffic layer

def test_persona_profiles():
    chrome = stealth.pick_persona("chrome-win")
    headers = stealth.base_headers(chrome)
    assert headers["User-Agent"].startswith("Mozilla/5.0 (Windows NT 10.0")
    assert "sec-ch-ua" in headers          # Chromium-family hint headers
    assert headers["Sec-Fetch-Mode"] == "navigate"

    safari = stealth.pick_persona("safari-mac")
    safari_headers = stealth.base_headers(safari)
    assert "sec-ch-ua" not in safari_headers  # Safari doesn't send client hints

    with pytest.raises(ValueError):
        stealth.pick_persona("netscape-communicator")


def test_jitter_bounds():
    for _ in range(20):
        d = stealth.jittered_delay(1.0, 2.0)
        assert 1.0 <= d <= 3.0
    assert stealth.jittered_delay(0.0, 0.0) == 0.0


def test_covert_headers_reach_server(mock):
    """Persona headers + Referer must actually arrive at the server."""
    httpclient.init_networking(persona="chrome-win")
    payload = httpclient.get_json(f"{mock}wpbuddy-echo", referer=f"{mock}about/")
    assert payload["ua"].startswith("Mozilla/5.0")
    assert payload["sec_ch_ua"] and "Chrome" in payload["sec_ch_ua"]
    assert payload["accept_language"].startswith("en-US")
    assert payload["referer"] == f"{mock}about/"


def test_covert_curl_cffi_backend(mock):
    """With curl_cffi installed, --covert impersonates a browser TLS/HTTP2 stack."""
    pytest.importorskip("curl_cffi")
    httpclient.init_networking(persona="firefox-linux", impersonate=True)
    assert httpclient.config.HTTP_BACKEND == "curl_cffi"
    resp = httpclient.get(f"{mock}wpbuddy-echo")
    assert resp is not None and resp.status_code == 200
    assert resp.json()["ua"].startswith("Mozilla/5.0 (X11; Linux")
