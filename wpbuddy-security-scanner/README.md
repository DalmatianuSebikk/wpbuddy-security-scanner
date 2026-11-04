# WpBuddy - WordPress Vulnerability Scanner

and also my Bachelor's Degree Project :D

An open-source vulnerability scanner for websites that use WordPress. WpBuddy identifies
and matches known vulnerabilities for the WordPress core version and for plugins/themes
(via the [wpvulnerability.net](https://www.wpvulnerability.net) open API), enumerates
users, probes XML-RPC, tests weak credentials, and can **gather a component's source
code and audit it locally** to find live issues that no database knows about yet.

The 0.4.0 release turned the flat scanner into a small toolkit: `wpbuddy scan`,
`wpbuddy exploit`, `wpbuddy db`, `wpbuddy report diff` and the live TUI **flow**
observatory - with the hard-gated engagement model (authorization, budgets,
allowed effects) on top. The flat `python main.py --target ...` form still works
and is equivalent to `wpbuddy scan`.

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
python main.py --target https://example.com/ --json                          # + machine-readable knowledge graph
python main.py --target https://example.com/ --source-dir ~/licensed-zips    # + audit commercial/custom code you own
python main.py --target https://example.com/ --profile deep                  # + aggressive read-only discovery
python main.py --target https://example.com/ --offline                       # no internet: scan from the cached vuln DB
```

```bash
wpbuddy scan --target https://example.com/     # same engine via the subcommand form
wpbuddy flow                                   # live TUI observatory / run launcher
wpbuddy db update                              # refresh the local vulnerability DB cache
```

Full options: `python main.py --help` (flat mode), or per subcommand: `wpbuddy scan|exploit|db|report|flow --help`

| Phase | What it does |
|---|---|
| **Passive** (GET-only, stealthy) | core version (**all sources collected and cross-checked**: meta generator / core CSS `?ver=` / RSS / readme.html - agreeing sources corroborate, disagreeing ones are reported as a discrepancy), plugin+theme discovery across crawled pages (sitemap-aware; **same-site references only** - third-party `wp-content` URLs in page content are filtered out as false positives, multi-part suffixes like `.co.uk` handled correctly), **content fingerprinting** (shortcodes, body classes, JS globals, cookies, headers, REST namespaces - catches plugins that leave no URL traces), version crawling from readme.txt / style.css (a readable readme on the target = proof of installation; soft-404/challenge pages are rejected before any version regex runs), vulnerability matching via wpvulnerability.net **with confidence tiers on every finding**, REST `/wp-json/` namespace fingerprinting, robots.txt review, sensitive-file exposure (soft-404- and WAF-challenge-aware, content-signature verified), missing security headers, **error-page analysis** (5xx/PHP fatals collected across all phases: server paths, plugins/themes in stack traces, visible security layers) |
| **Active** | user enumeration (REST collection -> per-id `?rest_route=` -> `?author=` redirects), XML-RPC probe (`system.listMethods`, flags `pingback.ping`/`system.multicall`), **plugin slug brute-force** (`--enum-plugins`, uses the live wordpress.org popular ranking, probes `wp-content/plugins/<slug>/readme.txt`; a blanket-deny probe runs first so a WAF 403ing the whole path class can't make every slug look installed) |
| **Access assessment** (`--access` / `--user`) | quiet alternatives to brute force: open-registration check (if registration is open, that *is* access), login-error differential to confirm which usernames are real, then a **targeted password spray** - a dozen high-probability candidates (target-derived `{host}{year}!` templates + top leaked passwords), one attempt per user per round, staying under lockout thresholds. `--via-xmlrpc` folds an entire spray round (N users) into ONE `system.multicall` request. The loud full-dictionary path still exists behind `--dict` |
| **Code audit** | mirrors component source from exposed directory listings (itself a finding) or downloads the exact detected version from the official wordpress.org distribution (never touches the target), then runs a pattern-based PHP analyzer (webshell patterns, SQLi, command exec, file inclusion, SSRF, reflected XSS, missing nonces). With `--verify-pocs`, findings become evidence: safely-testable rules are **reproduced live on the target** with benign payloads (reflected-XSS marker, harmless LFI file, error-based SQL probe). Every exploitable finding is written to a **Burp-ready PoC pack** |

The report is written as Markdown (default `outputScan.md`); gathered code-audit
sources and the PoC pack land in CWD `wpbuddy-audit/<host>/` for manual review, while
run timelines and run evidence record under the runs root (`--runs-dir`, default
`~/.wpbuddy/previous-runs/`). With `--json`, the scan also
produces `<output>.json` - a knowledge graph of the site (see below).

## Flow observatory (TUI)

The whole scan flow - phases, checks, findings, event log - is visible on one screen,
live or replayed from a recorded run. `wpbuddy flow` with no arguments opens a launcher
first: type a target, tick what the run should do (deep discovery, slug enumeration,
access test, code audit, PoC verification, JSON graph, failure gate), or pick a previous
run from the list (Enter replays it). `c` copies the equivalent CLI command - the
launcher is sugar over the canonical flags:

```bash
pip install 'wpbuddy[tui]'                                    # optional extra (Textual)
wpbuddy flow                                                  # launcher: pick target + functionality
wpbuddy flow --target https://example.com/                    # watch a live scan
wpbuddy flow --run ~/.wpbuddy/previous-runs/<host>/runs/<id>  # replay a recorded run
```

Every scan records its run under `~/.wpbuddy/previous-runs/<host>/runs/<id>/` (timeline,
engagement, artifacts) no matter which directory you started it from; `--runs-dir DIR`
(scans and flow) points the runs root somewhere else.

## Confidence model

Every finding is only as good as its weakest evidence link, so nothing is reported as
bare fact. Each version and vulnerability carries an earned **confidence tier**:

| Tier | Meaning | Typical evidence |
|---|---|---|
| **CONFIRMED** (>= 80/100) | multiple independent sources agree, or content was verified on the target | readable readme + fingerprint + explicit `Stable tag:` + advisory with a matched version range |
| **LIKELY** (>= 55) | one strong source | `meta generator` tag, enumeration 200 |
| **UNVERIFIED** (>= 20) | heuristic lead - review before acting on it | content fingerprint alone, page reference |
| **ASSUMED** (< 20) | the scanner defaulted because data was missing | advisory with **no version range recorded** - applicability assumed |

The score combines three chained links: **presence** (how the component was found:
enumeration > readme readable > error-page trace > fingerprint > page reference > manual
list), **version provenance** (explicit `Stable tag:` > theme style.css > number scraped
near a changelog anchor) and **applicability** (the advisory's real version range vs an
"assumed" default). Core-version sources are cross-checked: agreement corroborates,
disagreement (stale cache, unpatched readme.html) is flagged in the report.

With `--json` the same facts leave the scanner as a machine-readable graph: nodes for
components (with their evidence sources, versions, scores) and vulnerabilities (with
severity and applicability basis), edges for `site runs component` and
`component affected-by vulnerability` - ready for post-scan tooling, diffing scans over
time, or importing into your reporting stack.

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
reports it in a dedicated section. Only responses **from the scan target** are
fingerprinted: the scanner also talks to wpvulnerability.net, NVD and wordpress.org
through the same HTTP layer, and a firewall on those hosts must never be reported as
the target's. It also recognizes WAF **challenge interstitials served with HTTP 200**
("One moment, please..."-style pages): they are matched against the site's not-found
signature and error/challenge markers, so a challenge in front of every URL becomes
"findings unreliable" instead of nine false exposures.

When a probe is blocked (403/406/501), the request is retried through a ladder of
path-obfuscation variants (`/./`, `//`, percent-encoded slashes, case variation, `;`
segment params) - only after the plain request failed, so unfiltered targets pay
nothing, and only variants that returned a *real* answer count as a bypass in the
report. A 429 is never answered with more probes: it arms a scan-wide cool-down that
escalates (5s -> 10s -> 20s..., capped at 60s, `Retry-After` honoured) until any
successful response resets it - being rate-limited makes the scanner quieter, not
louder. If the network fails repeatedly, later requests drop to single attempts until
the target answers again. Disable the path fallback with `--no-evade`. This exists to
test whether a WAF provides prevention or just detection - a WAF that falls to path
normalization needs tuning.

## Project layout

```
main.py                 entry point (thin wrapper)
wpbuddy/
  cli.py                argument parsing and scan orchestration
  engine/               shared phase graph, typed event bus, scan engine, report finalization
  runs/store.py         append-only run log: meta.json + events.jsonl, replay iterator
  httpclient.py         single HTTP layer: timeouts, UA rotation, retries, delay
  vulndb.py             wpvulnerability.net client + version/operator matching
  versioning.py, report.py, config.py
  passive/              core_version, content discovery, fingerprints, readme crawling, files, REST
  active/               users, xmlrpc, credentials, access (quiet spray), enumerate (slug brute-force)
  codeaudit/            gather (target listing / wordpress.org), analyzer (PHP rules), poc (verification + Burp pack)
data/                   plugin list, spray list, dictionary, persona data
tests/                  mock WordPress site + pytest suite (runs offline)
```

### Inspecting a run

The CLI and the TUI share one phase graph (`wpbuddy/engine/phases.py`).
Every run appends typed events to `<runs-dir>/<host>/runs/<run_id>/events.jsonl`
(`--runs-dir`, default `~/.wpbuddy/previous-runs/`; disable with `--no-run-log`)
and records `meta.json` next to it. Runs recorded before the stable runs root
(under CWD `wpbuddy-audit/`) remain openable with `wpbuddy flow --run <path>`.

```bash
python main.py --target https://example.com/ --plan       # resolved phases + skip reasons
python main.py --target https://example.com/ --explain    # annotate decisions while scanning
```

`--plan` sends no requests. Every phase documents its purpose, preconditions,
inputs, outputs, effects and subphases; skips are explicit reasons, never
silent.

## Development

```bash
uv pip install -e . --group dev
pytest                 # spins up a local mock WordPress site, no internet needed
python tests/mockwp_server.py   # standalone mock site for manual testing on :8765
```

The mock site in `tests/fixtures/mockwp/` implements a WordPress-flavoured homepage,
sitemap, REST API, `?author=` redirects, wp-login.php and xmlrpc.php - enough to
exercise the whole pipeline without touching a real target.

## Changelog

### v0.4.0

The scanner grew from one flat command into a toolkit: a shared scan engine with a typed
event log, CLI subcommands, a live TUI observatory, a hard-gated engagement model, an
aggressive deep-discovery profile and the first exploitation stage - with the public
review's result-breaking bug wave fully resolved.

**Added**
- **shared scan engine + typed event log**: one phase graph drives CLI and TUI; `--plan` (resolved phases + explicit skip reasons, sends no requests) and `--explain` annotate every decision; every run appends to an **append-only run store** (`meta.json` + `events.jsonl`) with a replay iterator
- **CLI subcommands** - `wpbuddy scan`, `wpbuddy exploit`, `wpbuddy db`, `wpbuddy report diff`, `wpbuddy flow`; the flat flag form (`python main.py --target ...`) stays valid
- **Flow TUI** (`pip install 'wpbuddy[tui]'`): single-screen live observatory (live scan or replay); `wpbuddy flow` opens a **launcher** - type a target, tick functionalities, or pick a previous run; runs record under `~/.wpbuddy/previous-runs/` regardless of CWD (`--runs-dir` to relocate)
- **engagement model** - `--authorization`, `--exclude-path`, `--allow-effect`, `--max-requests`, `--max-time`: write effects are hard-gated and budgets stop the scan instead of warning
- **`--profile deep`** - aggressive read-only discovery: recursive crawl + JS/form mining, REST route inventory, a content-discovery mutation engine, async request pool with AIMD pacing
- **exploit engine starter** (`wpbuddy exploit`): template-driven, evidence tiers `reachable` -> `payload-sent` -> `signal-observed` -> `artifact`, evidence artifacts per run, plan-first gates before anything fires
- **local vulnerability DB cache**: `--offline` scans from a primed cache; `wpbuddy db status|update` shows and refreshes it
- **risk scoring + Remediation priorities + executive summary**: findings ranked by score, a prioritized fix list, a one-paragraph overview; `--diff` compares two report runs, `--fail-on` gates CI, `--suppressions` silences reviewed findings
- **authenticated mode**: `--cookie` / `--app-password` for scanning behind wp-login
- **mirror-vs-official integrity check**: files deployed on the target compared against the official wordpress.org distribution (defacement/webshell detection)
- **asset `?ver=` version detection**: component versions read from static-asset query strings when readmes are unreadable
- **bundled-dependency SCA**: known-vulnerable libraries shipped inside plugins/themes, found in gathered sources
- **malware/webshell/secret scan**: gathered sources checked for malicious patterns and leaked credentials
- **TLS / DNS / email posture**: certificate protocol version and expiry, SPF/DMARC/CAA of the registrable domain
- **extra checks**: wp-cron exposure, leftover install/upgrade pages, REST CORS reflection, login cookie flags, unauthenticated admin-ajax heartbeat
- **PoC verifier hardening**: content signatures instead of bare status codes, multi-parameter payloads, a per-PoC time budget
- **optional Semgrep pack** (`--semgrep`): the analyzer's rules as a configurable Semgrep pass
- `--timestamp-output`, `--mask-secrets`, a `schema` field in the JSON graph, more wp-config leak variants (`.bak`, `~`, `.save`, `.txt`, `.copy`, ...)

**Changed**
- the public review's result-breaking wave is fixed - **all P0-P2 items in issues.md are resolved**: target URLs normalized (query/fragment stripped, root-path fallback), `--stealth` no longer probes target listings, cached audit sources keep their mirror semantics (`.origin` marker), a vulnerability-DB outage reports "lookup failed" instead of "no vulnerabilities", every NVD CPE range is evaluated (not only the first), `preg /e` inside single-quoted patterns is detected, apex/www/subdomain hosts match in WAF and error-page collection - plus the false-positive and report-shape fixes (junk-page filtering, challenge-aware slug checks, HSTS not flagged on plain HTTP, 2FA-safe login detection, numbered lists, validated CLI numbers, and more)

### v0.3.0

Better vulnerability confirmation and recon coverage, inspired by published
CVE-hunting and bug-hunting workflows.

**Added**
- **multi-method source gathering** for the code audit: operator-provided
  archives (`--source-dir`, for commercial plugins and custom code where a
  licensed copy is the only legitimate source) -> the wordpress.org info
  API's per-version download links (kills URL-naming edge cases, says
  definitively when a component is not hosted there) -> the classic direct
  URL guess. Every successful extraction is version-verified (the archive's
  own `Version:`/`Stable tag:` must match; mismatches are audited but loudly
  labelled), and the report lists each ungatherable component with the
  actual reason instead of a console shrug
- **Upstream data hygiene** (wpvulnerability.net serves occasional garbage):
  advisory names that are really scraped error-page titles ("404 Page Not
  Found") are replaced by their CVE id; version bounds stated in advisory
  titles ("<plugin> <= 7.5.0") are cross-checked against the installed
  version, and a contradiction demotes the finding to a `contradicted` basis
  ("likely already patched, kept for review").
- **NVD enrichment for core CVEs**: findings the API gives no version range
  for ("applicability assumed") are looked up in NVD's CPE criteria - an
  explicit range turns them `bounded` or `refuted` (never silently dropped).
  Rate-limited and cached; failures keep the original basis. Set
  `NVD_API_KEY` to raise the rate limit.
- **`ajax-handler-no-auth` analyzer rule** (the Claude+Semgrep CVE-hunting
  join, in two static passes): `wp_ajax_nopriv_*`/`wp_ajax_*`/`admin_post_*`
  callbacks whose bodies contain no `current_user_can`/nonce check - HIGH
  when unauthenticated, MEDIUM when a Subscriber suffices. `is_admin()` is
  deliberately not accepted as authorization (request context, not
  capabilities).
- **Wider sensitive-file coverage**: `wp-config.php.old/.orig`, root-level
  `backup.zip`/`wordpress.zip`/`db.sql` (ZIPs confirmed by magic bytes, not
  status codes), `phpinfo.php`, `.htpasswd`.
- **Setup-wizard check**: `wp-admin/setup-config.php` serving the
  configuration form on a deployed site (config-overwrite/takeover risk);
  the polite "wp-config.php already exists" answer is recognized as safe.
- **Dangling external references**: hosts still linked by the crawled pages
  that no longer resolve in DNS (broken-link-hijacking starting point) -
  detection only, takeover proving stays with the engagement.
- REST user enumeration now requests `per_page=100` (the default caps
  listings at 10 users).

**Fixed**
- version bounds are parsed from advisory URLs too: Wordfence encodes the
  affected ceiling in the link slug with dots stripped
  ("...-custom-post-order-313-..." = 3.1.3), Patchstack keeps dots - the
  last standing false positive on our test site
- `csrf-no-nonce` fired on PSR-4 class/namespace files that WordPress
  autoloads but never routes directly (Yoast conditionals); endpoint
  detection is now content-based (files registering hooks/menus/routes)
- findings inside bundled vendor/test code (Twig's eval, PHPUnit helpers)
  are demoted one severity step and labelled as not plugin-author code
- the error-page section no longer claims path/component disclosure for
  bare HTML error pages that contain none
- version bounds are parsed from advisory **descriptions** too, not just
  titles - the false-positive class that survived the title-only parser
  (bare-CVE advisories carrying "<= 7.5.0" in the body, and core advisories
  listing whole range sets like "7.1 before 7.1.1; 7.0 through 7.0.4")
- the AJAX no-auth rule follows one hop of same-file delegation (the thin
  wrapper -> helper-with-check_ajax_referer pattern) and accepts framework
  nonce wrappers (`verify_nonce`); both caused false positives on Yoast SEO
- robots.txt: an empty `Disallow:` could swallow the newline and report the
  next line's first word ("Sitemap:") as a hidden path
- the audit cache directory now includes the component version - a cached
  download of 2.1 was previously audited and reported as the running 2.4
- report shape: LOW/INFO audit findings compressed to a count line instead
  of burying HIGH/MEDIUM evidence; multi-paragraph advisory descriptions
  truncated to one line; clean-plugin list condensed; list bullets no
  longer double-spaced
- advisory junk-name filter tightened so real titles ("Error Log Viewer
  <= 2.1 - XSS") survive it

**Fixed** (earlier in 0.3.0 development)
- WAF fingerprinting and error-page collection inspected every response passing
  through the HTTP layer, so a firewall on wpvulnerability.net/NVD could be
  reported as the *target's* WAF (found while A/B-testing 0.3.0 against the
  mock: a third-party "Imperva" body triggered a detection). Both collectors
  now only trust responses from the scan target's host.

### v0.2.0

Complete restructure of the initial flat-script scanner into the `wpbuddy/` package,
plus an offline test suite and a confidence layer that labels every finding with how
it is actually known.

**Added**
- **Confidence model** (`wpbuddy/confidence.py`): evidence-scored tiers
  (CONFIRMED / LIKELY / UNVERIFIED / ASSUMED) on every version and vulnerability,
  combining presence evidence, version provenance and advisory applicability;
  core-version **corroboration** (all sources collected, agreement boosts,
  disagreement flagged as a stale-cache/honeypot signal); advisory **applicability
  basis** rendered per CVE ("version range matched" vs "no range recorded -
  applicability assumed"); `--json` exports the scan as a **knowledge graph**
  (components, evidence, vulnerabilities as nodes/edges).
- **Covert mode** (`--covert`, `--persona`, `--jitter`): browser personas with
  correctly-ordered header sets, optional curl_cffi TLS/HTTP2 impersonation,
  human-like jitter pacing, referer chains, shuffled slug probing.
- **WAF awareness** (`waf.py`): passive firewall fingerprinting from headers,
  cookies and block pages, block detection and bypass accounting; path-obfuscation
  fallback (`obfuscate.py`) that only fires after a plain request was blocked.
- **Access assessment** (`--access` / `--user`): open-registration check,
  login-error user validation, targeted password spray (one attempt per user per
  round), `--via-xmlrpc` multicall spray, loud full-dictionary path behind `--dict`.
- **Code audit phase** (`--audit-code`, `--verify-pocs`): mirror component source
  from exposed listings or download the exact version from wordpress.org, local
  pattern-based PHP analyzer with false-positive controls, live PoC verification
  with benign payloads, Burp-ready PoC pack.
- **Plugin slug enumeration** (`--enum-plugins`): live wordpress.org popular
  ranking, obfuscation-aware probing.
- Offline test suite: 66 pytest tests against a local mock WordPress site
  (including a simulated WAF that blocks plain readme probes).

**Fixed**
- WAF **challenge pages served with HTTP 200** (Cloudflare "One moment, please...")
  no longer produce false "possible exposure" findings on every sensitive file, and
  robots.txt no longer dumps the challenge page as its content (error/challenge
  markers + a soft-404 baseline whose length tolerance scales with page size).
- **Phantom plugin versions / phantom CVEs**: readme responses are checked against
  the site's not-found signature before any version regex runs, and
  "Requires PHP 7.4" / "Tested up to WordPress 6.0" lines are no longer misread as
  the component's version.
- `--enum-plugins` counted a blanket WAF 403 as "plugin installed" - a bogus-slug
  probe now runs first, and only real 200 answers count when the path class is
  denied wholesale.
- **429 rate-limiting** triggered the 5-variant evasion ladder; it now arms an
  escalating scan-wide cool-down (Retry-After honoured) instead.
- The promised "continuing with single attempts" circuit breaker after repeated
  network failures is now actually implemented.
- Password sprays stop when wp-login.php / xmlrpc.php becomes unreachable instead
  of grinding every remaining user and round.
- XML-RPC `system.multicall` parser aligned results with a single regex and
  silently discarded found credentials on real WordPress (mixed success/fault
  batches); it now walks per-call items, and the mock server speaks the real
  WordPress fault shape.
- Same-site reference check treated every `*.co.uk` host as the target's own site
  (last-two-labels registrable-domain heuristic); multi-part public suffixes are
  handled.

### v0.1.0

Initial upload: flat-script scanner (passive/active scan, credential testing).

## Credits
- Vulnerability data: [wpvulnerability.net](https://www.wpvulnerability.net) open API
- Component source for offline auditing: the official [wordpress.org](https://wordpress.org) plugin/theme distribution
- Made by Sebastian Ionel - github.com/DalmatianuSebikk
