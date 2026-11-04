"""WpBuddy command line interface."""

import argparse
import json
import sys
import time
from datetime import datetime
from urllib.parse import urlparse, urlsplit, urlunsplit

from . import __version__, confidence, config, httpclient
from .engagement import EFFECTS, Budget, Engagement
from .engine import reporting
from .report import Report
from .tui.art import CLI_BANNER as BANNER

# Backwards-compatible private aliases (the helpers used to live in this file).
_BAND_ORDER = reporting.BAND_ORDER
_fail_on_check = reporting.fail_on_check
_severity_band = reporting.severity_band
_suppressed = reporting.suppressed
_write_diff_section = reporting.write_diff_section
_write_exec_summary = reporting.write_exec_summary
_write_priorities = reporting.write_priorities


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
    parser.add_argument("--semgrep", action="store_true",
                        help="Code audit: additionally run the bundled Semgrep rule pack "
                             "over gathered sources (optional: needs a semgrep binary on PATH)")
    parser.add_argument("--plan", action="store_true",
                        help="Print the resolved phase plan (including skip reasons) and exit "
                             "without sending a request")
    parser.add_argument("--explain", action="store_true",
                        help="Annotate every phase boundary, check, skip, WAF event and "
                             "confidence computation on stdout while scanning")
    parser.add_argument("--no-run-log", action="store_true",
                        help="Do not write the append-only run log "
                             "(wpbuddy-audit/<host>/runs/<run_id>/events.jsonl)")
    parser.add_argument("--authorization", metavar="TEXT",
                        help="Engagement scope (roadmap 2.3/9): text proving authorization for "
                             "this target (contract id, ticket, owner name); stored with the run")
    parser.add_argument("--exclude-path", action="append", default=[], metavar="PREFIX",
                        help="Never request paths under this prefix (repeatable), e.g. /wp-admin/")
    parser.add_argument("--allow-effect", action="append", default=[], metavar="EFFECT",
                        choices=EFFECTS,
                        help="Allow a state-changing effect for this run (repeatable): "
                             + ", ".join(EFFECTS) + ". Default allows read-only work")
    parser.add_argument("--max-requests", type=int, default=None, metavar="N",
                        help="Hard request ceiling for the whole run (budget enforcement)")
    parser.add_argument("--max-time", type=float, default=None, metavar="SECONDS",
                        help="Hard wall-clock ceiling for the whole run")
    parser.add_argument("--profile", choices=("safe", "deep"), default="safe",
                        help="Aggression profile (roadmap 1/3): safe = the default "
                             "GET-only scan; deep = adds recursive crawling, REST route "
                             "inventory and content discovery - more requests, still "
                             "no writes (default: %(default)s)")
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


# roadmap §2.2 - the CLI splits into subcommands; the historic flat flag
# interface keeps working (it IS the scan subcommand) so no operator script
# or test breaks. post/lab land with their roadmap stages.
SUBCOMMANDS = ("scan", "exploit", "post", "db", "report", "lab")

_SUBCOMMAND_HELP = """------------------------------------------------------------------
Subcommands (roadmap section 2.2) - the flat flag interface stays valid
and is equivalent to 'wpbuddy scan':
  wpbuddy scan --target URL [flags]   passive + active + code audit scan
  wpbuddy exploit --target URL        exploitation engine (plan-first)
  wpbuddy post cleanup --run ID       replay a run's cleanup log
  wpbuddy db status|update            local vulnerability cache (F-1)
  wpbuddy report diff A.json B.json   compare two scan graphs
  wpbuddy lab ...                     lab matrix (roadmap section 8)
------------------------------------------------------------------"""


def _dispatch_subcommand(name, argv):
    from . import exploit as exploit_cmd
    if name == "scan":
        _cmd_scan(argv)
    elif name == "exploit":
        exploit_cmd.main(argv)
    elif name == "db":
        _run_db_command(argv)
        sys.exit(0)
    elif name == "report":
        _cmd_report(argv)
    else:
        print(f"'{name}' is scaffolded but not implemented yet - it lands with its "
              f"roadmap stage (see exploitation-roadmap.md).")
        sys.exit(2)


def _cmd_report(argv):
    """`wpbuddy report diff` - graph comparison without a new scan (roadmap §2.2)."""
    from .confidence import ScanModel
    parser = argparse.ArgumentParser(prog="wpbuddy report", description="Report tooling")
    sub = parser.add_subparsers(dest="report_command", required=True)
    diff = sub.add_parser("diff", help="Compare two knowledge-graph JSONs")
    diff.add_argument("previous", help="the earlier --json graph")
    diff.add_argument("current", help="the later --json graph")
    args = parser.parse_args(argv)

    from pathlib import Path
    try:
        previous = json.loads(Path(args.previous).read_text(encoding="utf-8"))
        current = json.loads(Path(args.current).read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        parser.error(f"could not read graphs: {e}")

    changes = ScanModel.graph_diff(previous, current)
    if not any(changes.values()):
        print("No component or vulnerability changes between the two graphs.")
        sys.exit(0)
    for component in changes["new_components"]:
        print(f"+ component: {component}")
    for component in changes["gone_components"]:
        print(f"- component: {component}")
    for component, label in changes["new_findings"]:
        print(f"+ finding:   {component}: {label}")
    for component, label in changes["resolved_findings"]:
        print(f"- finding:   {component}: {label}")
    sys.exit(0)


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] in SUBCOMMANDS:
        _dispatch_subcommand(argv[0], argv[1:])
        return
    _cmd_scan(argv)


def _cmd_scan(argv=None):
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
    if not args.plan:
        httpclient.init_networking(persona=args.persona, proxy=args.proxy,
                                   impersonate=args.covert)

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

    suppressions = config.load_lines(args.suppressions) if args.suppressions else []

    # Engagement (roadmap 2.3): scope, authorization, budgets, allowed
    # effects. Every run carries its own contract; state-changing work is
    # impossible without explicitly allowing its effect.
    engagement = Engagement(
        target=target, host=config.TARGET_HOST,
        authorization=args.authorization,
        excluded_paths=tuple(args.exclude_path),
        max_requests=args.max_requests, max_seconds=args.max_time,
        allowed_effects=tuple({"read", *args.allow_effect}),
    )
    config.ENGAGEMENT = engagement
    config.RUN_BUDGET = Budget.from_engagement(engagement)
    if args.allow_effect:
        print(f"[*] Engagement allows effects beyond read-only: "
              f"{', '.join(args.allow_effect)}")
    if not engagement.authorization and args.allow_effect:
        print("[!] Warning: state-changing effects are allowed but --authorization is "
              "empty - record the consent reference for the audit trail")

    # One report/model/bus for the whole run: every phase writes to them and
    # every decision is recorded, whether or not a view is attached.
    report = Report()
    report.title(f"WpBuddy scan report for {target}")
    report.paragraph(f"Scanned with WpBuddy {__version__} on a target supplied by the operator. "
                     f"Findings are leads for an authorized security assessment.")
    model = confidence.ScanModel()

    from .engine.events import EventBus
    from .engine.phases import default_graph
    from .engine.run import ScanContext, ScanEngine, TargetUnreachable
    from .runs.store import RunStore

    bus = EventBus()
    store = None if (args.no_run_log or args.plan) else RunStore(config.TARGET_HOST)
    ctx = ScanContext(target=target, args=args, report=report, model=model, bus=bus,
                      dict_list=dict_list, suppressions=suppressions, output=output,
                      json_output=args.json, diff=args.diff,
                      engagement=engagement)
    engine = ScanEngine(ctx, graph=default_graph(), store=store, explain=args.explain)

    if args.plan:
        print(f"WpBuddy {__version__} - scan plan for {target}")
        for stage, title in (("run", "Run stage"), ("finalize", "Finalize stage "
                                                   "(always runs, even after a crash)")):
            print(f"\n{title}:")
            for phase, marker, note in engine.plan_lines():
                if phase.stage != stage:
                    continue
                print(f"  {marker} {phase.id:<16} {phase.title} - {phase.purpose}"
                      + (f"\n      {note}" if note else ""))
        sys.exit(0)

    print(f"WpBuddy {__version__} - target: {target}")
    if args.stealth:
        print("[*] Stealth mode: passive phase only")
    if suppressions:
        print(f"[*] {len(suppressions)} suppression pattern(s) loaded")
    if args.explain:
        print("[*] Explain mode: annotating phase boundaries and decisions")
    print("Starting the scanner...")

    exit_code = 0
    status = "ok"
    try:
        engine.begin(argv)
        engine.run()
    except TargetUnreachable:
        # Cheap liveness gate: if even the homepage is unreachable, don't spend
        # minutes retrying every subsequent request against a dead host.
        print("[!] Target is unreachable; nothing to scan.")
        report.paragraph("The target could not be reached; no checks were performed.")
        status, exit_code = "unreachable", 1
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user - writing partial report")
        status, exit_code = "interrupted", 130
    except Exception as e:
        # A crash in one phase must never cost the operator the findings
        # already collected.
        print(f"[!] Scanner error in a later phase: {e!r} - writing partial report")
        report.paragraph(f"\n> Scan aborted early due to an internal error: `{e!r}`. "
                         f"Findings above this line were completed.")
        status, exit_code = "error", 1
    finally:
        # WAF/error pages collected across ALL phases and the report itself are
        # finalized from here, so a crashed phase still yields a partial report.
        engine.finalize(status)
        if ctx.fail_reason or ctx.write_failed:
            exit_code = 1

    sys.exit(exit_code)


if __name__ == "__main__":
    main()
