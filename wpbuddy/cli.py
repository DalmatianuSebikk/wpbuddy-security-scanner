"""WpBuddy command line interface."""

import argparse
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
