# WpBuddy — issue backlog for automated fixing

Working copy: `wpbuddy-security-scanner/`
Target: Python 3.10+, existing test suite must stay green.

## How to work this file

- Fix in severity order unless a task says otherwise. One logical change per commit.
- For every bug fix, **add a regression test** that fails before and passes after.
- Run `pytest -q` before declaring done. All 92 existing tests must still pass.
- Do not rename public CLI flags, report sections, JSON node/edge shapes, or the `wpbuddy-audit/` layout without saying so.
- Keep the style of the surrounding code (docstrings explaining *why*, defensive behaviour, no new runtime dependencies unless the task allows it).
- Mark a checkbox `[x]` only when code + test are both done.
- If a fix is ambiguous or would change reported semantics, leave a short `# NOTE:` in the code and explain in the task section rather than guessing silently.

Environment:

```bash
uv pip install -e '.[covert]' --group dev   # or use the existing .venv
pytest -q
```

---

## P0 — result-breaking bugs

### [x] P0-1 — Normalize target URLs (query/fragment must not break paths) (1907164)

- **Files:** `wpbuddy/cli.py:126-132`
- **Current:** target is only stripped and slash-appended. `--target https://x/?utm=1` yields `https://x/?utm=1/robots.txt`, so every subsequent path lands in the query string.
- **Fix:** parse with `urllib.parse.urlsplit`, drop `query` and `fragment`, force path `/` when empty, rebuild with `urlunsplit`, then append a trailing slash. Keep the existing `http://`/`https://` validation. Reject targets whose hostname is empty.
- **Acceptance test:** `cli.main(["--target", "https://example.com/?utm=x#top", ...])` reaches `https://example.com/robots.txt`, `.../wp-json/`, `.../xmlrpc.php` (assert with a fake HTTP layer or the mock server plus a sent-URL recorder).
- **Also test:** query-only target does not double-slash; target with a path (`https://x/blog`) keeps `/blog/`.

### [x] P0-2 — `--stealth` must not touch the target after the passive phase (1f7e7b0)

- **Files:** `wpbuddy/cli.py:110-113, 180-185`
- **Current:** `--stealth` skips `active.run()` but still calls `codeaudit.run()` with the default `--audit-code auto`, which probes directory listings on the target. Help text says “Passive phase only”.
- **Fix:** when `args.stealth` is set and the operator did not explicitly pass `--audit-code`, run the audit in `source` mode (wordpress.org only) or `off`. If the operator explicitly passes `--audit-code auto|target` with `--stealth`, print a warning that target requests will occur.
- **Acceptance test:** scan the mock with `--stealth`, record every request URL; after the last passive request, no `/wp-content/plugins/<slug>/` listing probe is made. A second test with `--stealth --audit-code target` asserts the warning is printed.

### [x] P0-3 — Cached mirrored sources must keep their mirror semantics (8ac8944)

- **Files:** `wpbuddy/codeaudit/__init__.py:62-66, 75`; `wpbuddy/codeaudit/poc.py:59-64`
- **Current:** a cached source gets origin `"cached from a previous scan (v)"`, and `mirrored = "mirrored" in origin` is `False`. The analyzer then sees paths prefixed with `target/` and PoC URLs become `.../wp-content/plugins/target/wp-content/plugins/<slug>/...` (double prefix). Verified repro below.
- **Repro:**

```python
# create wpbuddy-audit/example.test/plugin-vuln-1.0/target/wp-content/plugins/vuln/vuln.php
# then run codeaudit.run(..., {'plugins': {'vuln': '1.0'}}, args(verify_pocs=True))
# url_for_finding gives .../wp-content/plugins/target/wp-content/plugins/vuln/vuln.php
```

- **Fix:** persist how the cache was produced. Simplest correct approach: store a small marker file (e.g. `.origin` containing `mirrored`/`official`) next to the cached tree, or infer it from `path/"target"` existing, and derive both `source` and `mirrored` from it. For cached mirrors, analyze `path/"target"` so relative paths start at `wp-content/...`.
- **Acceptance test:** the repro above must produce `.../wp-content/plugins/vuln/vuln.php` and finding files starting with `wp-content/`.
- **Related:** write the marker only after a successful, non-partial gather.

### [x] P0-4 — Distinguish “database unreachable” from “no vulnerabilities” (92de7ea)

- **Files:** `wpbuddy/vulndb.py:100-133`; `wpbuddy/passive/__init__.py:82-85, 177-186, 245-263`
- **Current:** `core_vulnerabilities()` returns `[]` when `_fetch` fails, and the report says “No known vulnerabilities in the wpvulnerability.net database”. An API outage reads as a clean site. Plugin/theme use `None` internally but print equally confident clean/not-in-DB text.
- **Fix:** make lookups return `None` when transport/JSON/API failure occurred and `[]` only for a real empty result. Thread that through: core section says “lookup failed / database unreachable”, plugin/theme sections say the same instead of “not in database” or “no known vulnerabilities”. Keep `None` for invalid/unknown slug as well, but add a distinct reason if cheap (e.g. a `LookupResult` or `(data, status)` tuple is fine if tests are updated).
- **Acceptance test:** monkeypatch `vulndb._fetch` to `None` (failure) and assert the report contains “database unreachable”/“lookup failed” and **not** “No known vulnerabilities”; monkeypatch a successful payload with `vulnerability: null` and assert “not present in the database”.

### [x] P0-5 — Check every NVD CPE range, not only the first (40d871e)

- **Files:** `wpbuddy/vulndb.py:288-323`; caller `:225-251`
- **Current:** `_nvd_parse_operator` returns on the first `cpeMatch` with any operator. A CVE with ranges `< 6.5.0` and `6.6.0–6.7.0` refutes an installed `6.6.8`.
- **Repro:** the payload in the review: first range `versionEndExcluding 6.5.0`, second range `versionStartIncluding 6.6.0` / `versionEndExcluding 6.7.0`; `_nvd_parse_operator` returns `{max_version: 6.5.0, max_operator: lt}` → `is_affected("6.6.8", ...)` is `False`.
- **Fix:** return a list of operators (all `wordpress:wordpress` CPE ranges). `enrich_core_with_nvd` marks `bounded` if **any** operator reports affected and `refuted` only if **every** range excludes the version. Cache the list.
- **Acceptance test:** the repro must become `bounded`; an installed version outside every range must still become `refuted`; a CPE for a plugin under the same CVE must still be ignored.

### [x] P0-6 — Make `preg-e-modifier` work on single-quoted patterns (f590f3f)

- **Files:** `wpbuddy/codeaudit/analyzer.py:61-75, 105-108`
- **Current:** `code_view()` replaces the whole single-quoted literal with `''`, so the rule never sees `/e`.
- **Fix:** for this rule (or for string-preserving rules generally), match against a view that keeps single-quoted literal contents. Add a `raw`-view flag to the rule tuple or a dedicated check in `_scan_file`. Do not break the string-literal false-positive controls for other rules.
- **Acceptance test:** `preg_replace('/foo/e', '$1', $y)` is HIGH `preg-e-modifier`; `preg_replace('/foo/', 'b', $y)` is not. Keep the existing double-quoted case working.

### [x] P0-7 — Accept same-site hosts (apex ↔ www/subdomain) in WAF and error-page collection (bb387f4)

- **Files:** `wpbuddy/waf.py:57-60`; `wpbuddy/passive/errorpages.py:55-58`
- **Current:** exact `host != config.TARGET_HOST` check. Scanning `https://example.com` when the site redirects to `www.example.com` disables both collectors entirely.
- **Fix:** reuse `passive/content._same_site(host, config.TARGET_HOST)` (watch the import cycle: import inside the function). Still reject third-party API hosts (`wpvulnerability.net`, NVD, wordpress.org).
- **Acceptance test:** set `config.TARGET_HOST = "example.com"`; feed a response with `url="https://www.example.com/x"`, a Cloudflare header, and a PHP fatal body; assert WAF detection and one collected error entry. Feed `https://api.wordpress.org/x` and assert it is ignored.

---

## P1 — false positives / false negatives

### [ ] P1-1 — Advisory bounds that include the installed version must become `bounded`

- **Files:** `wpbuddy/vulndb.py:168-212`
- **Current:** `_upper_bounds` is only used to demote to `contradicted` when every bound excludes the version. A matching bound leaves the basis at `assumed` (−20 confidence), so dozens of clearly bounded findings render as `[ASSUMED]`.
- **Fix:** if `basis != "bounded"` but bounds were found: if every bound excludes the installed version → `contradicted`; otherwise → `bounded` (the advisory’s own range includes the version). Keep the URL-bound “digits” handling.
- **Acceptance test:** installed `6.6.8` with title “WordPress <= 6.9.1” → `bounded`; with “<= 6.5.0” → `contradicted`; multiple bounds where one includes the version → `bounded`.
- **Note:** this changes scoring only; update any test asserting `assumed` for title-bounded cases.

### [ ] P1-2 — Slug enumeration must reject challenge/soft-404 200s

- **Files:** `wpbuddy/active/enumerate.py:55-67`
- **Current:** any HTTP 200 counts as installed; a WAF 200 interstitial installed every slug.
- **Fix:** for a 200 answer, call `passive.files.response_is_junk(resp, target)` and only count when false. Compute the junk/soft-404 baseline once before the loop (it is cached anyway).
- **Acceptance test:** mock handler returns the challenge body with 200 for every readme probe → zero installed; a real readme body → installed.

### [ ] P1-3 — Tighten `response_is_junk` so real readmes survive

- **Files:** `wpbuddy/passive/files.py:97-103, 287-299`
- **Current:** any of “not found”, “access denied”, “one moment”, etc. anywhere in the first 4000 bytes is junk. A real changelog line “Link not found fixed” discards the readme.
- **Fix options, in order of preference:**
  1. Only run the marker check when the body is small / looks like an error page (e.g. `<html`, `<title`, short body, status != 200).
  2. Or require the marker to appear in the first ~1500 bytes and combine with an HTML/error shape.
  Keep the baseline match as the primary signal. Challenge detection must still work for the existing tests.
- **Acceptance test:** the “Stable tag: 2.1 … Link not found fixed” readme passes; a Cloudflare “One moment, please…” page fails; a 404-article does not pass.

### [ ] P1-4 — Do not report HSTS as missing on plain HTTP

- **Files:** `wpbuddy/passive/files.py:34-40, 110-134`
- **Fix:** build the expected header set per scheme; skip `Strict-Transport-Security` when the target scheme is `http`. Mention in the section that HTTPS is required.
- **Acceptance test:** `http://x/` output does not list HSTS; `https://x/` does.

### [ ] P1-5 — Strip `www` from spray password templates

- **Files:** `wpbuddy/active/access.py:84-92`
- **Fix:** normalize the host label: lowercase, strip a leading `www.`, drop everything after the first `.`, fall back to `target`.
- **Acceptance test:** `spray_candidates("https://www.example.com/")` starts with `example<year>!`, not `www<year>!`.

### [ ] P1-6 — `--audit-code target` must explain failures and honor `--source-dir`

- **Files:** `wpbuddy/codeaudit/__init__.py:111-128`
- **Current:** no listing → `(None, None, None)` and the component silently disappears. `target` mode never consults `source_dir`.
- **Fix:** return `"no-listing"` as the reason when target mode finds nothing, and add it to `_GATHER_REASONS`. In target mode, after a failed listing, still try `gather_from_wordpress(..., source_dir=...)` **only** for the operator archive (not wordpress.org) — or document that target mode is listing-only and make `--source-dir` imply a fallback. Pick one and test it.
- **Acceptance test:** target mode + no listing → unaudited bullet naming the component; `--source-dir` with an exact archive is used even in target mode.

### [ ] P1-7 — Report exposed directory listings as a real finding

- **Files:** `wpbuddy/passive/files.py:398-409`; `wpbuddy/codeaudit/__init__.py:113-118`
- **Current:** `check_directory_listing` is dead; the only trace is a log line and the audit origin string.
- **Fix:** call it for every discovered component in the passive phase (or once per component during audit), and add a report bullet with severity/recommendation (“disable `Options -Indexes` / block listing”). The section should be its own finding, not just audit provenance.
- **Acceptance test:** mock listing under `wp-content/plugins/<slug>/` → report contains a directory-listing finding with the URL.

### [ ] P1-8 — Crawl for themes like plugins (no homepage-only shortcut)

- **Files:** `wpbuddy/passive/__init__.py:220-264`
- **Fix:** pass the already-crawled pages into `_scan_themes` instead of re-fetching only the homepage. Reuse the `refs`/`artifacts` from `run()`.
- **Acceptance test:** mock page that references a theme only on an inner page → theme discovered.

### [ ] P1-9 — 2FA-safe login success detection

- **Files:** `wpbuddy/active/credentials.py:42-49`
- **Current:** any final URL containing `wp-login.php` means failure; a 2FA challenge after a correct password is reported as a wrong password.
- **Fix:** success if the chain reached `/wp-admin` (history or final URL), or if the final `wp-login.php` response is a challenge rather than the login form. Detect challenge markers (`two-factor`, `2fa`, `verification code`, `authenticator`) and a missing password field; add a distinct “credentials valid, MFA pending” result.
- **Acceptance test:** mock returns redirect → `wp-login.php?action=2fa` with a code field → reported as valid-with-MFA, not failed.

### [ ] P1-10 — Ship package data and fix the version metadata

- **Files:** `pyproject.toml:2-3, 8-12, 28-29`; `wpbuddy/config.py:6`
- **Fix:**
  - Bump the project version to the real value and keep it in sync with `wpbuddy/__init__.py` (single source: read it in `pyproject` via hatch or bump both in one commit).
  - Add `[tool.hatch.build.targets.wheel] include = ["wpbuddy", "data"]` (or move the data into `wpbuddy/data/` and use `importlib.resources` — preferred, but larger). At minimum the wheel must contain `pluginList.txt`, `sprayPasswords.txt`, `numeparola.txt`.
  - Make `config.DATA_DIR` resolve correctly for an installed wheel.
- **Acceptance test:** `uv build --wheel`, inspect the zip: all three data files present, metadata version equals `wpbuddy.__version__`; run a scan from a temp CWD using only the installed wheel (no repo `data/`).
- **Note:** the review confirmed the wheel currently has **zero** data files and version `0.2.0` while `__init__.py` says `0.3.0`.

### [ ] P1-11 — Do not trust a partial cache; clean failed extractions

- **Files:** `wpbuddy/codeaudit/__init__.py:62-66`; `wpbuddy/codeaudit/gather.py:188-200, 220-235`
- **Fix:** only treat a cache directory as valid when it is complete (marker file written after success, P0-3). On `BadZipFile`/`OSError` or an interrupted download, remove the destination subtree. A partial mirror (some files fetched) must not be labelled a full source; either retry the official source or add a “partial” label.
- **Acceptance test:** corrupt cache dir without marker → re-gather; failed extraction leaves no directory behind.

---

## P2 — UX, robustness, hygiene

### [ ] P2-1 — Create parent directories for `--output`

- **Files:** `wpbuddy/report.py:46-48`
- **Fix:** `Path(path).parent.mkdir(parents=True, exist_ok=True)` before writing; same for the JSON graph and PoC pack.
- **Test:** `Report().write("nested/dir/r.md")` succeeds.

### [ ] P2-2 — Fix numbered lists

- **Files:** `wpbuddy/report.py:36-38`
- **Fix:** add one `OrderedList` for the whole iterable, not one per item.
- **Test:** output contains `1.`, `2.`, `3.`.

### [ ] P2-3 — Validate CLI numeric arguments

- **Files:** `wpbuddy/cli.py` (`--timeout`, `--delay`, `--jitter`, `--max-pages`, `--max-users`, `--enum-limit`)
- **Fix:** reject `--timeout <= 0`, negative delay/jitter; allow `0` for pages/users/limit. Use `parser.error` so the exit code is 2 and the message is actionable.
- **Test:** each invalid value exits 2 with the flag named.

### [ ] P2-4 — Warn on conflicting phase flags

- **Files:** `wpbuddy/cli.py`
- **Fix:** `--stealth` + `--access`/`--user`/`--dict` → warning that credential testing will not run; `--dict` without access/user → warning that the dictionary is unused (or auto-enable access — document the choice).
- **Test:** both warnings are printed on the mock.

### [ ] P2-5 — DNS lookup timeout

- **Files:** `wpbuddy/passive/dangling.py:66-71`
- **Fix:** run `getaddrinfo` in a small helper with a timeout (e.g. `concurrent.futures.ThreadPoolExecutor` + `future.result(timeout=3)`). A timeout must not abort the remaining hosts.
- **Test:** monkeypatch a hanging resolver; check returns within the budget and later hosts are still processed.

### [ ] P2-6 — Escape target-controlled text in Markdown

- **Files:** `wpbuddy/report.py`, plus callers that interpolate headers/robots/advisories
- **Fix:** add `escape_md(text)` (backticks, `*`, `_`, `[`, `]`, leading `#`/`>`/`-`) and apply it to header values, server values and advisory names/links. Keep fenced code bodies raw, but guard against closing fences.
- **Test:** a plugin slug with `*`/backticks and a header value with `#` render literally.

### [ ] P2-7 — Put found credentials in the JSON graph (optionally mask console output)

- **Files:** `wpbuddy/active/access.py:203-211`; `wpbuddy/confidence.py`
- **Fix:** add a `credentials` node/edge (user + password, or a hash with `--mask-secrets`) to the graph. Add `--mask-secrets` for console/report output.
- **Test:** JSON contains the found user/password; masked mode does not contain the plaintext.

### [ ] P2-8 — Expand the default dictionary and add a newline

- **Files:** `data/numeparola.txt`
- **Fix:** add a few hundred common/leaked passwords (or document that a real list must be supplied). Keep `sprayPasswords.txt` small and curated. Ensure files end with a newline.
- **Test:** `config.load_lines()` returns > 200 entries for the dictionary.

### [ ] P2-9 — Remove unused imports and dead code (or wire it up)

- **Files:** `wpbuddy/cli.py:5` (`Path`); `wpbuddy/report.py:4` (`Bold`, `Italic`, `Link`); `wpbuddy/active/__init__.py:9` (`credentials`); `xmlrpc.bruteforce`; `files.check_directory_listing`
- **Fix:** delete unused imports; keep `credentials` imported if used by tests, otherwise update tests. Wire `check_directory_listing` per P1-7. Add a lint config (`ruff`) with an unused-import rule.
- **Test:** `ruff check wpbuddy` is clean.

### [ ] P2-10 — Repo hygiene

- [ ] Add `LICENSE` (MIT, already declared in `pyproject`).
- [ ] Untrack the four root `__pycache__/*.pyc` files (`git rm --cached`).
- [ ] Add `.github/workflows/ci.yml` running `ruff` + `pytest` on 3.10–3.12.
- [ ] Add `SECURITY.md` (authorized-scan policy, disclosure) and a JSON-schema/version field for the knowledge graph.
- [ ] Add `--timestamp-output` or auto-naming so reports are not overwritten.

### [ ] P2-11 — Fix test isolation

- **Files:** `tests/test_pipeline.py:20-34`
- **Fix:** autouse-reset `files`, `waf`, `errorpages`, `httpclient` globals/session, `config.TARGET_HOST`, `config.PERSONA`, and all `config.*` overrides after each test. Add a fixture for the sent-URL recorder used by P0-2.
- **Test:** run a WAF test and a clean test in both orders with `-p no:randomly` / repeated runs; no leakage.

---

## Feature backlog (separate from bugs)

Do not start these until P0/P1 are green. Each should get its own design note.

- **F-1 Local vulnerability DB + `--offline`**: SQLite import of WPScan/Patchstack/Wordfence feeds, `wpbuddy db update`, schema version, TTL. Removes the single-API dependency and makes evaluation reproducible.
- **F-2 Risk scoring**: CVSS × exposure (unauth/auth) × confidence × patch availability; sort findings by risk; remediation priority section.
- **F-3 Authenticated mode**: `--cookie`, `--app-password`; auth matrix (route → required capability); reach admin-ajax/REST.
- **F-4 Core integrity + modified-file detection**: official checksums API; optional wordpress.org SVN comparison for plugins.
- **F-5 Version detection from static assets**: `?ver=` on plugin CSS/JS, hashed asset names, without readme dependency.
- **F-6 Bundled-dependency SCA**: parse `composer.lock`/`package.json`; map to vulnerable library versions.
- **F-7 Malware/webshell + secret scan** of mirrored files (entropy, eval chains, key patterns).
- **F-8 DNS/email/TLS posture** (SPF, DMARC, DKIM, cert expiry/protocol, CAA) and verified subdomain-takeover fingerprints.
- **F-9 More active checks**: pingback SSRF callback, `wp-cron.php`, REST CORS, cookie flags, public `admin-ajax` actions, `install.php`/`upgrade.php`, more `wp-config` variants.
- **F-10 Reporting**: HTML/PDF, executive summary, scan metadata, `--diff` against a previous JSON graph, SARIF, `--fail-on`, suppression/allowlist file.
- **F-11 PoC verifier hardening**: per-rule confirmation signals, multi-parameter payloads, request/time budget.
- **F-12 PHP tokenizer/AST taint analysis or optional Semgrep rules.**
- **F-13 Bulk inventory/resume/schedule + read-only web UI/TUI.**
- **F-14 i18n (EN/RO).**

---

## Definition of done

- [ ] Regression test added and fails on the pre-fix commit.
- [ ] `pytest -q` green.
- [ ] `ruff check wpbuddy tests` green.
- [ ] No new runtime dependency unless the task allows it.
- [ ] Report/section wording updated where behaviour changed.
- [ ] Issue checkbox ticked with the commit hash in parentheses.
