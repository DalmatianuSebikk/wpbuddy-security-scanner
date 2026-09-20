"""End-to-end tests against the local mock WordPress site (no real network
except where explicitly noted; vulnerability DB responses are stubbed)."""

import json
import zipfile
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


def test_sensitive_files_dynamic_page_drift(monkeypatch):
    """Challenge pages that change size every request (ray ids, timestamps) still
    match the baseline: the old +/-48 byte tolerance missed the ~100-byte drift."""
    from wpbuddy import httpclient
    import itertools

    counter = itertools.count()

    def fake_get(url, **kwargs):
        n = next(counter)  # every response slightly bigger, like a real challenge
        return FakeResp(200, "<html><body>interstitial " + "y" * (12000 + n * 37) + "</body></html>")

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
    monkeypatch.setattr(vulndb, "plugin_vulnerabilities", lambda slug: [{"fake": 1}])
    errorpages.inspect(FakeResp(500, ECOMEDBT_TRACE, url="https://ecomedbt.ro/?author=1"))
    report = Report()
    errorpages.write_report(report, known_plugins={"wordfence"})
    text = report.doc.write()
    assert "server path disclosed: `/home/ecomedbt/public_html/`" in text
    assert "**dp-preloader**" in text and "1 recorded vulnerabilities" in text
    assert "Wordfence" in text


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


# ---------------------------------------------------------------- confidence model

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
