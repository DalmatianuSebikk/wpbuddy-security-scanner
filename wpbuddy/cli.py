"""WpBuddy command line interface."""

import argparse
import sys
from pathlib import Path

from . import __version__, active, codeaudit, config, confidence, httpclient, passive
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
                             "targeted spray (uses --passwordList, default numeparola.txt)")
    parser.add_argument("--passwordList",
                        help="Custom password list: spray candidates (default data/sprayPasswords.txt) "
                             "or the full dictionary with --dict (default data/numeparola.txt)")
    parser.add_argument("--output", default="outputScan",
                        help="Output report path without extension (default: outputScan -> outputScan.md)")
    parser.add_argument("--json", action="store_true",
                        help="Also write <output>.json: the scan's knowledge graph - components, "
                             "versions, evidence sources, confidence tiers and vulnerabilities "
                             "as nodes/edges for later tooling")
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
    parser.add_argument("--audit-code", choices=("auto", "target", "source", "off"), default="auto",
                        help="Gather component code and analyze it locally: auto (listing, then "
                             "wordpress.org), target (only exposed listings), source (only "
                             "wordpress.org, never touches the target), off (default: %(default)s)")
    parser.add_argument("--version", action="version", version=f"WpBuddy {__version__}")
    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)

    target = args.target.strip()
    if not target.startswith(("http://", "https://")):
        print("Target must start with http:// or https://")
        sys.exit(1)
    if not target.endswith("/"):
        target += "/"

    # Apply global HTTP settings chosen on the CLI.
    config.DEFAULT_TIMEOUT = args.timeout
    config.REQUEST_DELAY = args.delay
    config.REQUEST_JITTER = args.jitter if args.jitter is not None else (1.5 if args.covert else 0.0)
    config.EVADE = not args.no_evade
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
            active.run(report, target, args, dict_list=dict_list)
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
