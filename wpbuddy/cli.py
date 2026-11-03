"""WpBuddy command line interface."""

import argparse
import json
import sys
import time
from datetime import datetime
from urllib.parse import urlparse, urlsplit, urlunsplit

from . import __version__, active, codeaudit, confidence, config, httpclient, passive
from .report import Report

BANNER = """
    ██╗    ██╗    ██╗
    ██║    ╚██╗   ██║
    ██║     ╚██╗ ██╔╝
    ██║      ╚████╔╝
    ██║       ╚██╔╝
    ╚═╝        ╚═╝
    WpBuddy - WordPress vulnerability scanner
    ------------------------------------------------------------------
    An open-source vulnerability scanner for websites using WordPress.
    Identifies and matches vulnerabilities for the core version and for
    plugins/themes, tests weak credentials, and audits component source
    code locally. Passive, active (stealthy/invasive) and code-audit
    phases can be tuned from the CLI.

    Disclaimer:
    - this project is related to Website Security and must not be used
      for malicious activities.
    - never scan a website you do not own or are not authorized to test.
    ------------------------------------------------------------------
"""


def build_parser():
    parser = argparse.ArgumentParser(
        prog="WpBuddy",
        description=BANNER,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""------------------------------------------------------------------
Examples:
  python main.py --target https://example.com/
  python main.py --target https://example.com/ --stealth --audit-code source
  python main.py --target https://example.com/ --access --via-xmlrpc
  python main.py --target https://example.com/ --user admin --dict
  python main.py --target https://example.com/ --enum-plugins --verify-pocs
------------------------------------------------------------------""",
    )
    parser.add_argument("--target", required=True,
                        help="Target website, including http:// or https://")
    parser.add_argument("--pluginList",
                        help="Path to a plugin slug list checked in addition to discovered ones "
                             "(default: data/pluginList.txt; pass an empty string '' to disable it "
                             "and scan only what the site itself reveals)")
    parser.add_argument("--access", action="store_true",
                        help="Access assessment: open-registration check, login-error user "
                             "validation, then a targeted password spray (few high-probability "
                             "passwords, one attempt per user per round - much quieter than "
                             "brute force)")
    parser.add_argument("--user",
                        help="Restrict the access assessment to one username (also enables it)")
    parser.add_argument("--dict", action="store_true",
                        help="Opt into the loud path: full dictionary attack instead of the "
                             "targeted spray (uses --passwordList, default numeparola.txt). "
                             "No effect without --access/--user - credential testing is opt-in")
    parser.add_argument("--passwordList",
                        help="Custom password list: spray candidates (default data/sprayPasswords.txt) "
                             "or the full dictionary with --dict (default data/numeparola.txt)")
    parser.add_argument("--output", default="outputScan",
                        help="Output report path without extension (default: outputScan -> outputScan.md)")
    parser.add_argument("--timestamp-output", action="store_true",
                        help="Append a timestamp to the output name (outputScan-20261104-1930.md) "
                             "so repeated scans never overwrite earlier reports")
    parser.add_argument("--json", action="store_true",
                        help="Also write <output>.json: the scan's knowledge graph - components, "
                             "versions, evidence sources, confidence tiers and vulnerabilities "
                             "as nodes/edges for later tooling")
    parser.add_argument("--mask-secrets", action="store_true",
                        help="Mask discovered passwords in console and Markdown output "
                             "(the JSON knowledge graph keeps the real values for tooling)")
    parser.add_argument("--timeout", type=float, default=config.DEFAULT_TIMEOUT,
                        help="Per-request timeout in seconds (default: %(default)s)")
    parser.add_argument("--delay", type=float, default=0.0,
                        help="Politeness delay in seconds between requests (default: 0)")
    parser.add_argument("--max-pages", type=int, default=config.MAX_CRAWL_PAGES,
                        help="How many pages to crawl for plugin/theme references (default: %(default)s)")
    parser.add_argument("--max-users", type=int, default=config.MAX_USER_IDS,
                        help="Highest user id to probe during enumeration (default: %(default)s)")
    parser.add_argument("--via-xmlrpc", action="store_true",
                        help="Run the credential attack through XML-RPC system.multicall instead of wp-login.php")
    parser.add_argument("--stealth", action="store_true",
                        help="Passive phase only: no user enumeration fallbacks, no XML-RPC probe, no credential attack")
    parser.add_argument("--covert", action="store_true",
                        help="Traffic camouflage for authorized engagements: browser-persona headers, "
                             "TLS/HTTP2 impersonation (needs the optional curl_cffi extra), "
                             "Referer chains and human-like jitter pacing")
    parser.add_argument("--persona", choices=("chrome-win", "edge-win", "safari-mac", "firefox-linux"),
                        help="Browser persona used for the whole scan (default: random pick)")
    parser.add_argument("--jitter", type=float, default=None,
                        help="Extra random pause of 0..JITTER seconds per request "
                             "(default: 1.5 with --covert, else 0)")
    parser.add_argument("--proxy",
                        help="Route all traffic through an HTTP(S) proxy, e.g. http://127.0.0.1:8080 "
                             "(also handy to route the scanner through Burp)")
    parser.add_argument("--no-evade", action="store_true",
                        help="Disable the WAF-evasion fallback: blocked probes stay blocked instead "
                             "of being retried through path-obfuscation variants")
    parser.add_argument("--enum-plugins", action="store_true",
                        help="Brute-force popular plugin slugs against wp-content/plugins/ "
                             "(invasive: one request per slug; the slug list is fetched live "
                             "from the wordpress.org popular ranking)")
    parser.add_argument("--enum-limit", type=int, default=config.DEFAULT_ENUM_LIMIT,
                        help="Slug count for --enum-plugins (default: %(default)s)")
    parser.add_argument("--verify-pocs", action="store_true",
                        help="Attempt to reproduce code-audit findings on the target with benign "
                             "payloads (reflected-XSS markers, harmless LFI files, error-based SQL); "
                             "dangerous rules only get manual curl templates")
    parser.add_argument("--audit-code", choices=("auto", "target", "source", "off"), default=None,
                        help="Gather component code and analyze it locally: auto (listing, then "
                             "wordpress.org), target (only exposed listings), source (only "
                             "wordpress.org, never touches the target), off (default: auto)")
    parser.add_argument("--source-dir", metavar="DIR",
                        help="Directory of operator-provided component archives for code the "
                             "audit cannot download (commercial plugins, custom themes): "
                             "named {kind}-{slug}-{version}.zip or {slug}-{version}.zip")
    parser.add_argument("--offline", action="store_true",
                        help="Serve vulnerability lookups from the local cache only - no requests "
                             "to wpvulnerability.net (prime it first with: wpbuddy db update)")
    parser.add_argument("--cookie",
                        help="Authenticated mode (F-3): raw Cookie header for the target, e.g. "
                             "'wordpress_logged_in_x=...;wordpress_test_cookie=...' - "
                             "attached to target requests only")
    parser.add_argument("--app-password", metavar="USER:TOKEN",
                        help="Authenticated mode (F-3): WordPress application password "
                             "(application password, not the login password) sent as Basic auth "
                             "to the target only")
    parser.add_argument("--diff", metavar="PREV_JSON",
                        help="Compare this scan's knowledge graph against a previous "
                             "--json output and report what changed (new/resolved findings)")
    parser.add_argument("--fail-on", choices=("none", "critical", "high", "medium", "any"),
                        default="none",
                        help="Exit with code 1 when a finding at or above this severity exists "
                             "(credentials always count as critical) (default: %(default)s)")
    parser.add_argument("--suppressions", metavar="FILE",
                        help="File of patterns (substring, case-insensitive) matched against "
                             "'component:name' of vulnerability findings; matches are excluded "
                             "from the priorities summary and --fail-on")
    parser.add_argument("--version", action="version", version=f"WpBuddy {__version__}")
    return parser


def _validate_numeric_args(parser, args):
    """Fail fast with an actionable message instead of misbehaving deep
    inside the scan (timeout<=0 surfaces as requests errors per request;
    negative delays/jitter as TypeErrors inside the pacing code).
    parser.error exits 2, argparse's argument-error code.
    """
    if args.timeout <= 0:
        parser.error(f"--timeout must be > 0 seconds (got {args.timeout})")
    if args.delay < 0:
        parser.error(f"--delay must be >= 0 seconds (got {args.delay})")
    if args.jitter is not None and args.jitter < 0:
        parser.error(f"--jitter must be >= 0 seconds (got {args.jitter})")
    if args.max_pages < 0:
        parser.error(f"--max-pages must be >= 0 (got {args.max_pages})")
    if args.max_users < 0:
        parser.error(f"--max-users must be >= 0 (got {args.max_users})")
    if args.enum_limit < 0:
        parser.error(f"--enum-limit must be >= 0 (got {args.enum_limit})")


def _normalize_target(raw):
    """Canonicalize an operator-supplied target URL.

    Query strings and fragments must never survive into the target: every
    later probe is built as `target + path`, so a `?utm=...` left in place
    would push every path into the query string
    (`https://x/?utm=1robots.txt`). Returns (normalized_url, None) on
    success or (None, error_message) when the target is unusable.
    """
    target = (raw or "").strip()
    if not target.startswith(("http://", "https://")):
        return None, "Target must start with http:// or https://"
    parts = urlsplit(target)
    if not parts.hostname:
        return None, "Target has no hostname"
    # force the root path when empty so a query-only target cannot become
    # 'https://x//' after the trailing slash is appended below
    target = urlunsplit((parts.scheme, parts.netloc, parts.path or "/", "", ""))
    if not target.endswith("/"):
        target += "/"
    return target, None


def explicitly_passed(argv, flag):
    """True when the operator wrote `flag` on the command line.

    argparse's default is indistinguishable from an explicit value that
    matches it, and behaviour differences (like P0-2's stealth downgrade)
    hinge on the operator's intent, not the value.
    """
    return any(arg == flag or arg.startswith(flag + "=") for arg in (argv if argv is not None else sys.argv[1:]))


def _run_db_command(argv):
    """`wpbuddy db status|update` - manage the local vulnerability cache (F-1).

    Kept as a tiny hand-rolled dispatch (checked before the flat scan parser)
    so the existing flag interface is untouched; a full subcommand split is
    roadmap work, not this feature.
    """
    from . import vulncache, vulndb
    parser = argparse.ArgumentParser(prog="wpbuddy db", description="Local vulnerability-database cache")
    sub = parser.add_subparsers(dest="db_command", required=True)
    sub.add_parser("status", help="Show what is cached and how old it is")
    sub.add_parser("update", help="Re-fetch every cached entry now")
    args = parser.parse_args(argv)

    cached = vulncache.entries()
    if args.db_command == "status":
        counts = vulncache.counts()
        if not cached:
            print(f"Cache is empty ({vulncache.cache_path()}); it fills as you scan, "
                  "or run: wpbuddy db update")
            return
        print(f"Cache: {vulncache.cache_path()} (schema v{vulncache.SCHEMA_VERSION})")
        for kind in sorted(counts):
            by_status = ", ".join(f"{n} {status}" for status, n in sorted(counts[kind].items()))
            print(f"  {kind}: {by_status}")
        ages = [row[3] for row in cached]
        print(f"  oldest entry: {(time.time() - min(ages)) / 3600:.1f}h ago, "
              f"newest: {(time.time() - max(ages)) / 3600:.1f}h ago "
              f"(TTL {vulncache.DEFAULT_TTL // 3600}h)")
        return

    if not cached:
        print("Cache is empty - nothing to update (scan something first).")
        return
    ok = fail = 0
    for kind, slug, _status, _age in cached:
        if vulndb.refresh_entry(kind, slug) is None:
            fail += 1
        else:
            ok += 1
    print(f"Refreshed {ok} entr{'y' if ok == 1 else 'ies'}"
          + (f", {fail} failed" if fail else ""))


def _write_priorities(report, model, suppressions=()):
    """The Remediation priorities section (F-2): what to fix first."""
    creds = model.credentials()
    risks = [r for r in model.risks() if not _suppressed(r, suppressions)]
    if suppressions:
        suppressed_count = len(model.risks()) - len(risks)
        if suppressed_count:
            print(f"[*] {suppressed_count} finding(s) suppressed from the priorities list")
    if not creds and not risks:
        return
    report.section("Remediation priorities")
    report.paragraph(
        "Ranked by risk = CVSS x exposure (unauthenticated > authenticated) x "
        "confidence in the finding. Work top-down; 'patch available' means a "
        "fixed release exists upstream, so updating clears the row.")
    if creds:
        report.paragraph(f"**Working credentials found for {len(creds)} account(s)** - "
                         "change these passwords (and revoke active sessions) before "
                         "anything else: " + ", ".join(f"`{c['user']}`" for c in creds))
    top = risks[:10]
    if top:
        report.bullets([
            f"**{r['risk']}** - {r['component']}: {r['name']}"
            + (f" (CVSS {r['severity']})" if r.get("severity") else "")
            + f" - {r['exposure']}"
            + (f", confidence {r['confidence']}/100" if r.get("confidence") is not None else "")
            + (", **patch available - update**" if r["patch_available"] else "")
            for r in top
        ])
    if len(risks) > len(top):
        report.paragraph(f"...and {len(risks) - len(top)} lower-risk findings in the "
                         "sections above.")


def _suppressed(risk_item, patterns):
    """True when a finding matches a --suppressions pattern."""
    if not patterns:
        return False
    haystack = f"{risk_item.get('component')}:{risk_item.get('name') or ''}".lower()
    return any(pattern.lower() in haystack for pattern in patterns)


def _severity_band(severity):
    """'critical'|'high'|'medium'|'low' from a severity string or CVSS number."""
    from . import risk
    text = str(severity or "").lower()
    for band in ("critical", "high", "medium", "low"):
        if band in text:
            return band
    cvss = risk.parse_cvss(severity)
    if cvss is None:
        return None
    if cvss >= 9.0:
        return "critical"
    if cvss >= 7.0:
        return "high"
    if cvss >= 4.0:
        return "medium"
    return "low"


_BAND_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def _write_exec_summary(report, model, metadata):
    """The executive summary, spliced in right under the title (F-10)."""
    summary = Report()
    summary.section("Executive summary")
    summary.paragraph(" | ".join(f"{key}: {value}" for key, value in metadata))

    components = model.components()
    by_type = {}
    for node in components:
        by_type[node["type"]] = by_type.get(node["type"], 0) + 1
    comp_text = ", ".join(f"{n} {kind}(s)" for kind, n in sorted(by_type.items())) or "none"

    risks = model.risks()
    bands = {}
    for item in risks:
        band = _severity_band(item.get("severity")) or "unknown"
        bands[band] = bands.get(band, 0) + 1
    creds = model.credentials()

    summary.paragraph(f"Components discovered: {comp_text}. Vulnerability findings: "
                     f"{len(risks)}"
                     + (" (" + ", ".join(f"{n} {band}" for band, n in sorted(
                         bands.items(), key=lambda kv: _BAND_ORDER.get(kv[0], 9))) + ")"
                        if bands else "")
                     + (f". **Working credentials: {len(creds)}**" if creds else "")
                     + ".")
    if risks:
        summary.paragraph("Highest risks right now:")
        summary.bullets([
            f"**{r['risk']}** - {r['component']}: {r['name']}"
            + (f" (CVSS {r['severity']})" if r.get("severity") else "")
            for r in risks[:3]
        ])
        summary.paragraph("Fix order and full detail: 'Remediation priorities' at the "
                          "end of this report; per-component findings above.")
    else:
        summary.paragraph("No vulnerability findings were recorded in this scan.")
    report.prepend(summary)


def _write_diff_section(report, model, previous_json_path, target):
    """What changed since the graph in previous_json_path (F-10)."""
    from pathlib import Path
    try:
        previous = json.loads(Path(previous_json_path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        print(f"[!] --diff: could not read previous graph ({e}); skipping")
        return
    prev_nodes = {n["id"]: n for n in previous.get("nodes", [])}
    current = model.to_dict(target)
    curr_nodes = {n["id"]: n for n in current["nodes"]}

    prev_components = {i for i, n in prev_nodes.items() if n.get("type") != "vulnerability"}
    curr_components = {i for i, n in curr_nodes.items() if n.get("type") != "vulnerability"}
    new_components = sorted(curr_components - prev_components)
    gone_components = sorted(prev_components - curr_components)

    def vuln_set(nodes):
        out = set()
        for edge in (previous.get("edges") if nodes is prev_nodes else current["edges"]):
            if edge.get("relation") != "affected-by":
                continue
            label = nodes.get(edge["to"], {}).get("label", "?")
            out.add((edge["from"], label))
        return out

    prev_vulns, curr_vulns = vuln_set(prev_nodes), vuln_set(curr_nodes)

    report.section("Changes since previous scan")
    if not (new_components or gone_components or prev_vulns or curr_vulns):
        report.paragraph("No component or vulnerability changes against the previous graph.")
        return
    if new_components:
        report.paragraph("New since the previous scan: " + ", ".join(f"`{c}`" for c in new_components))
    if gone_components:
        report.paragraph("No longer present: " + ", ".join(f"`{c}`" for c in gone_components))
    new_vulns = sorted(curr_vulns - prev_vulns)
    resolved = sorted(prev_vulns - curr_vulns)
    if new_vulns:
        report.paragraph("**New findings:**")
        report.bullets([f"{component}: {label}" for component, label in new_vulns])
    if resolved:
        report.paragraph("Resolved since the previous scan (update worked / component gone): "
                         + ", ".join(f"{component}: {label}" for component, label in resolved))


def _fail_on_check(model, fail_on, suppressions):
    """The --fail-on gate (F-10): returns a reason string or None."""
    if fail_on == "none":
        return None
    risks = [r for r in model.risks() if not _suppressed(r, suppressions)]
    if fail_on == "any":
        if model.credentials():
            return "working credentials were found"
        if risks:
            return f"{len(risks)} vulnerability finding(s)"
        return None
    threshold = _BAND_ORDER[fail_on]
    for item in risks:
        band = _severity_band(item.get("severity")) or "low"
        if _BAND_ORDER[band] <= threshold:
            return (f"{item['component']}: {item['name']} "
                    f"(severity {item.get('severity') or 'unrated'})")
    return None


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] == "db":
        _run_db_command(argv[1:])
        sys.exit(0)

    parser = build_parser()
    args = parser.parse_args(argv)
    _validate_numeric_args(parser, args)

    # Conflicting-flag warnings (P2-4): warn, never guess the operator's
    # intent. --dict alone does NOT auto-enable the access assessment -
    # credential testing is opt-in by design.
    if args.stealth and (args.access or args.user or args.dict):
        print("[!] Warning: --stealth runs the passive phase only - the credential "
              "assessment (--access/--user/--dict) will NOT run in this scan")
    if args.dict and not (args.access or args.user):
        print("[!] Warning: --dict without --access/--user - the dictionary is not "
              "used; credential testing only runs with --access or --user")

    target, error = _normalize_target(args.target)
    if error:
        print(error)
        sys.exit(1)
    config.TARGET_HOST = (urlparse(target).hostname or "").lower()

    # Authenticated mode (F-3): credentials are applied by httpclient to
    # target-host requests only.
    if args.app_password:
        user, sep, token = args.app_password.partition(":")
        if not sep or not token:
            print("--app-password must be USER:TOKEN (application password)")
            sys.exit(1)
        import base64
        config.AUTH_BASIC = base64.b64encode(f"{user}:{token}".encode()).decode()
        print(f"[*] Authenticated mode: application password for '{user}'")
    if args.cookie:
        config.AUTH_COOKIE = args.cookie
        print("[*] Authenticated mode: raw cookie supplied")

    # --stealth promises "passive phase only", but the default --audit-code
    # mode ('auto') probes directory listings ON the target. Without an
    # explicit operator choice, downgrade the audit to wordpress.org sources
    # (which never touch the target); with one, warn about the contradiction.
    args.audit_code = args.audit_code or "auto"
    if args.stealth and not explicitly_passed(argv, "--audit-code"):
        if args.audit_code in ("auto", "target"):
            args.audit_code = "source"
            print("[*] Stealth: code audit limited to official wordpress.org sources "
                  "(no requests to the target)")
    elif args.stealth and args.audit_code in ("auto", "target"):
        print(f"[!] Warning: --stealth with --audit-code {args.audit_code} still probes "
              f"directory listings on the target - requests WILL reach it")


    # Apply global HTTP settings chosen on the CLI.
    config.DEFAULT_TIMEOUT = args.timeout
    config.REQUEST_DELAY = args.delay
    config.REQUEST_JITTER = args.jitter if args.jitter is not None else (1.5 if args.covert else 0.0)
    config.EVADE = not args.no_evade
    config.OFFLINE = args.offline
    httpclient.init_networking(persona=args.persona, proxy=args.proxy, impersonate=args.covert)

    # Keep the original behaviour: fall back to the shipped plugin list.
    # (--pluginList "" explicitly disables the manual list - site-discovered only.)
    if args.pluginList is None:
        shipped = config.DATA_DIR / "pluginList.txt"
        if shipped.exists():
            args.pluginList = str(shipped)

    dict_list = None
    if args.dict:
        path = args.passwordList or config.DATA_DIR / "numeparola.txt"
        dict_list = config.load_lines(path)
        if not dict_list:
            print(f"[!] Dictionary is empty or unreadable: {path}")
            sys.exit(1)

    output = args.output[:-3] if args.output.endswith(".md") else args.output
    if args.timestamp_output:
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        output = f"{output}-{stamp}"
        print(f"[*] Timestamped output: {output}.md")

    print(f"WpBuddy {__version__} - target: {target}")
    if args.stealth:
        print("[*] Stealth mode: passive phase only")
    print("Starting the scanner...")

    report = Report()
    report.title(f"WpBuddy scan report for {target}")
    report.paragraph(f"Scanned with WpBuddy {__version__} on a target supplied by the operator. "
                     f"Findings are leads for an authorized security assessment.")

    exit_code = 0
    passive_results = {}
    model = confidence.ScanModel()
    started = time.monotonic()
    suppressions = config.load_lines(args.suppressions) if args.suppressions else []
    if suppressions:
        print(f"[*] {len(suppressions)} suppression pattern(s) loaded")
    try:
        # Cheap liveness gate: if even the homepage is unreachable, don't spend
        # minutes retrying every subsequent request against a dead host.
        probe = httpclient.get(target, retries=1)
        if probe is None:
            print("[!] Target is unreachable; nothing to scan.")
            report.paragraph("The target could not be reached; no checks were performed.")
            sys.exit(1)

        passive_results = passive.run(report, target, args, model=model)
        if not args.stealth:
            active.run(report, target, args, dict_list=dict_list, model=model)
        else:
            report.rule()
        codeaudit.run(report, target, passive_results, args)
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user - writing partial report")
        exit_code = 130
    except Exception as e:
        # A crash in one phase must never cost the operator the findings
        # already collected.
        print(f"[!] Scanner error in a later phase: {e!r} - writing partial report")
        report.paragraph(f"\n> Scan aborted early due to an internal error: `{e!r}`. "
                         f"Findings above this line were completed.")
        exit_code = 1
    finally:
        # WAF + error pages collected across ALL phases carry their own findings -
        # write them even when a phase crashed.
        try:
            from . import waf
            waf.write_report(report)
            from .passive import errorpages
            errorpages.write_report(report,
                                    known_plugins=set(passive_results.get("plugins", {})))
        except Exception as e:
            print(f"[*] Post-scan analysis skipped: {e}")
        try:
            _write_priorities(report, model, suppressions)
        except Exception as e:
            print(f"[*] Risk summary skipped: {e}")
        if args.diff:
            try:
                _write_diff_section(report, model, args.diff, target)
            except Exception as e:
                print(f"[*] Diff section skipped: {e}")
        try:
            duration = time.monotonic() - started
            metadata = [
                ("Target", target),
                ("WpBuddy", __version__),
                ("Scanned", datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
                ("Duration", f"{duration:.1f}s"),
                ("Profile", ("stealth " if args.stealth else "")
                           + (f"audit={args.audit_code} ")
                           + ("offline " if args.offline else "")
                           + (f"persona={args.persona}" if args.persona else "persona=auto")),
            ]
            _write_exec_summary(report, model, metadata)
        except Exception as e:
            print(f"[*] Executive summary skipped: {e}")
        fail_reason = None
        try:
            fail_reason = _fail_on_check(model, args.fail_on, suppressions)
        except Exception as e:
            print(f"[*] --fail-on check skipped: {e}")
        if fail_reason:
            exit_code = 1
            print(f"[!] --fail-on {args.fail_on}: {fail_reason}")
        report.write(f"{output}.md")
        print(f"[*] Report saved: {output}.md")
        if args.json:
            try:
                model.write_json(f"{output}.json", target)
                print(f"[*] Knowledge graph saved: {output}.json")
            except Exception as e:
                print(f"[!] Could not write the JSON graph: {e}")

    sys.exit(exit_code)


if __name__ == "__main__":
    main()
