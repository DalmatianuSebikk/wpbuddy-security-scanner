# WpBuddy - WordPress Vulnerability Scanner

and also my Bachelor's Degree Project :D

An open-source vulnerability scanner for websites that use WordPress. WpBuddy identifies
and matches known vulnerabilities for the WordPress core version and for plugins/themes
(via the [wpvulnerability.net](https://www.wpvulnerability.net) open API), enumerates
users, probes XML-RPC, tests weak credentials, and can **gather a component's source
code and audit it locally** to find live issues that no database knows about yet.

## Disclaimer
- this project is related to Website Security and is not a tool for malicious activities.
- you shall not misuse this tool to gain unauthorized access.
- only scan websites you own or are explicitly authorized to test.

## Installation

```bash
uv venv && uv pip install -e .        # or: python -m venv .venv && .venv/bin/pip install -e .
uv pip install -e '.[covert]'         # optional: browser TLS/HTTP2 impersonation for --covert
python main.py --version
```

Requires Python 3.10+. Runtime dependencies: `requests`, `beautifulsoup4`, `markdownmaker`.

## Usage

```bash
python main.py --target https://example.com/                                 # everything, defaults
python main.py --target https://example.com/ --stealth                       # passive phase only
python main.py --target https://example.com/ --audit-code source             # audit code via wordpress.org only
python main.py --target https://example.com/ --user admin                    # + credential testing (wp-login)
python main.py --target https://example.com/ --user admin --via-xmlrpc       # + credential testing (system.multicall)
python main.py --target https://example.com/ --enum-plugins --verify-pocs    # + slug brute-force + live PoCs
```

Full options: `python main.py --help`

| Phase | What it does |
|---|---|
| **Passive** (GET-only, stealthy) | core version (meta generator / core CSS `?ver=` / RSS / readme.html), plugin+theme discovery across crawled pages (sitemap-aware; **same-site references only** - third-party `wp-content` URLs in page content are filtered out as false positives), **content fingerprinting** (shortcodes, body classes, JS globals, cookies, headers, REST namespaces - catches plugins that leave no URL traces), version crawling from readme.txt / style.css (a readable readme on the target = proof of installation), vulnerability matching via wpvulnerability.net, REST `/wp-json/` namespace fingerprinting, robots.txt review, sensitive-file exposure (soft-404-aware, content-signature verified), missing security headers, **error-page analysis** (5xx/PHP fatals collected across all phases: server paths, plugins/themes in stack traces, visible security layers) |
| **Active** | user enumeration (REST collection -> per-id `?rest_route=` -> `?author=` redirects), XML-RPC probe (`system.listMethods`, flags `pingback.ping`/`system.multicall`), **plugin slug brute-force** (`--enum-plugins`, uses the live wordpress.org popular ranking, probes `wp-content/plugins/<slug>/readme.txt`) |
| **Access assessment** (`--access` / `--user`) | quiet alternatives to brute force: open-registration check (if registration is open, that *is* access), login-error differential to confirm which usernames are real, then a **targeted password spray** - a dozen high-probability candidates (target-derived `{host}{year}!` templates + top leaked passwords), one attempt per user per round, staying under lockout thresholds. `--via-xmlrpc` folds an entire spray round (N users) into ONE `system.multicall` request. The loud full-dictionary path still exists behind `--dict` |
| **Code audit** | mirrors component source from exposed directory listings (itself a finding) or downloads the exact detected version from the official wordpress.org distribution (never touches the target), then runs a pattern-based PHP analyzer (webshell patterns, SQLi, command exec, file inclusion, SSRF, reflected XSS, missing nonces). With `--verify-pocs`, findings become evidence: safely-testable rules are **reproduced live on the target** with benign payloads (reflected-XSS marker, harmless LFI file, error-based SQL probe). Every exploitable finding is written to a **Burp-ready PoC pack** |

The report is written as Markdown (default `outputScan.md`); gathered sources and audit
evidence land in `wpbuddy-audit/<host>/` for manual review.

## Burp Suite workflow

Every exploitable code-audit finding becomes a file in `wpbuddy-audit/<host>/pocs/`:
finding metadata (component, `file:line`, the matching source line, verified/not) followed
by a raw HTTP request with full browser headers - paste it straight into Burp Repeater and
fire. Verified findings are marked so you know which ones already reproduced. To watch the
scanner's own traffic in Burp, point it at the proxy: `--proxy http://127.0.0.1:8080`
(combine with `--covert` so the proxied requests look like a browser).

## Covert mode (authorized engagements / detection-rule testing)

`--covert` makes the scanner's traffic look like ordinary browsing instead of a scripted
client. Each flag addresses a specific detection signal:

| Signal WAFs/IDSs use | What WpBuddy does |
|---|---|
| Python TLS fingerprint (JA3/JA4) | optional `curl_cffi` backend impersonates a real browser's TLS ClientHello (`uv pip install '.[covert]'`) |
| HTTP/1.1-only client | HTTP/2 negotiated via curl_cffi |
| Bare 2-header requests | full browser header profiles (Accept, Accept-Language, sec-ch-ua, Sec-Fetch-*, ...) in real browser order |
| User-Agent changing every request | one random persona (Chrome/Edge/Safari/Firefox) per scan, consistent throughout - like a browser session |
| No Referer on sub-pages | referer chain while crawling (`--persona` to pin one) |
| Metronome-perfect pacing | `--jitter` adds uniform random silence (default 1.5s with `--covert`) |
| Dictionary-order brute force | slug enumeration probes in shuffled order |
| Scanner source IP | `--proxy http://host:port` - route through your engagement proxy/Burp |

```bash
uv pip install '.[covert]'
python main.py --target https://example.com/ --covert --persona chrome-win --jitter 2
```

Honest limits: covert mode changes how requests *look*, not how many are sent - volume
and behaviour-based detection still apply, and no header set makes an unauthorized scan
appropriate. Use it on engagements you're authorized to run, or to verify a client's own
WAF rules actually catch quiet scanners.

## WAF awareness & evasion

The scanner fingerprints the firewall layer passively (Cloudflare, Wordfence, Sucuri,
ModSecurity, AWS WAF, Imperva, LiteSpeed - from headers, cookies and block pages) and
reports it in a dedicated section. When a probe is blocked (403/406/429/501), the
request is retried through a ladder of path-obfuscation variants (`/./`, `//`,
percent-encoded slashes, case variation, `;` segment params) - only after the plain
request failed, so unfiltered targets pay nothing, and the report records which
technique got through. 429 rate-limiting triggers an automatic back-off. Disable the
fallback with `--no-evade`. This exists to test whether a WAF provides prevention or
just detection - a WAF that falls to path normalization needs tuning.

## Project layout

```
main.py                 entry point (thin wrapper)
wpbuddy/
  cli.py                argument parsing and scan orchestration
  httpclient.py         single HTTP layer: timeouts, UA rotation, retries, delay
  vulndb.py             wpvulnerability.net client + version/operator matching
  versioning.py, report.py, config.py
  passive/              core_version, content discovery, fingerprints, readme crawling, files, REST
  active/               users, xmlrpc, credentials, access (quiet spray), enumerate (slug brute-force)
  codeaudit/            gather (target listing / wordpress.org), analyzer (PHP rules), poc (verification + Burp pack)
data/                   plugin list, spray list, dictionary, persona data
tests/                  mock WordPress site + pytest suite (runs offline)
```

## Development

```bash
uv pip install -e . --group dev
pytest                 # spins up a local mock WordPress site, no internet needed
python tests/mockwp_server.py   # standalone mock site for manual testing on :8765
```

The mock site in `tests/fixtures/mockwp/` implements a WordPress-flavoured homepage,
sitemap, REST API, `?author=` redirects, wp-login.php and xmlrpc.php - enough to
exercise the whole pipeline without touching a real target.

## Credits
- Vulnerability data: [wpvulnerability.net](https://www.wpvulnerability.net) open API
- Component source for offline auditing: the official [wordpress.org](https://wordpress.org) plugin/theme distribution
- Made by Sebastian Ionel - github.com/DalmatianuSebikk
