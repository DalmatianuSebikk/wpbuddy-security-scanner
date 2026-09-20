"""Local code-audit phase: gather component source, analyze it, report.

For every plugin/theme discovered in the passive phase:
1. try to mirror its deployed code via directory listing on the target
   (mode 'target' and 'auto') - zero guessing, that IS the production code
2. otherwise download the exact detected version from the official
   wordpress.org distribution (mode 'source' and 'auto') - stealthy,
   the target is never contacted
3. run the pattern-based analyzer over the gathered source
4. optionally reproduce findings live (--verify-pocs) and ALWAYS emit a
   Burp-ready PoC pack (wpbuddy-audit/<host>/pocs/) with a raw HTTP request
   file per exploitable finding

Gathered code and findings land in ./wpbuddy-audit/<host>/ so everything can
be reviewed manually after the scan.
"""

from pathlib import Path
from urllib.parse import urlsplit

from .. import config
from . import analyzer, gather, poc

_MODES = ("auto", "target", "source", "off")


def run(report, target, passive_results, args):
    mode = getattr(args, "audit_code", "auto")
    if mode not in _MODES or mode == "off":
        return {}

    report.section("Local source-code audit")
    report.paragraph(
        "For each discovered component WpBuddy tries to obtain its source code - "
        "either by mirroring an exposed directory listing on the target, or by "
        "downloading the exact detected version from the official wordpress.org "
        "distribution (which does not touch the target at all) - and analyzes it "
        "locally with a pattern-based engine. Findings are leads, not proofs: "
        "review them with the file:line evidence below and the PoC pack.")
    report.paragraph(
        "**What the PoC requests are - and are not.** Each request in the pack is a "
        "*candidate* that reaches the file containing the flagged code with a benign "
        "marker. It is NOT a working exploit: a real exploit needs the parameter to "
        "actually flow to the vulnerable sink, which depends on how WordPress routes "
        "the request (admin-ajax, REST, front-end) and cannot be proven statically. "
        "For database CVEs, the advisory link next to each CVE above is where the "
        "verified exploitation steps live. Treat everything here as triage.")

    host = urlsplit(target).hostname or "target"
    workdir = Path("wpbuddy-audit") / host
    audited = {}
    pack_entries = []

    for kind, components in (("plugin", passive_results.get("plugins", {})),
                             ("theme", passive_results.get("themes", {}))):
        for slug, version in components.items():
            label = f"{kind} {slug}" + (f" {version}" if version else "")
            path = workdir / f"{kind}-{slug}"
            if path.exists():
                source = path
                origin = "cached from a previous scan"
            else:
                source, origin = _gather(mode, kind, slug, version, target, path)
            if source is None:
                continue
            findings = analyzer.analyze(source)
            mirrored = "mirrored" in origin
            if getattr(args, "verify_pocs", False) and findings:
                findings = poc.verify_findings(report, target, kind, findings, mirrored)
            _report_component(report, label, origin, source, findings)
            audited[slug] = findings
            pack_entries += [
                (label, f, f["poc"]["poc"])
                for f in findings
                if f.get("poc") and f["poc"].get("poc", {}).get("params")
            ]

    if not audited:
        report.paragraph("No component code could be gathered (no listings exposed and no "
                         "versions detected). Passive + database findings still apply.")
        return {}

    report.paragraph(f"Gathered sources and raw findings are kept under `{workdir.resolve()}` "
                     f"for manual review.")
    if pack_entries:
        files = poc.write_pack(workdir / "pocs", pack_entries)
        print(f"[*] PoC pack written: {len(files)} request files under {(workdir / 'pocs').resolve()}")
        report.paragraph(
            f"**PoC pack** - {len(files)} raw HTTP request files (Burp Repeater-ready) "
            f"written to `{(workdir / 'pocs').resolve()}`. Each file carries the finding, "
            f"the source line and the exact request; verified ones are marked. "
            f"Review every request before sending it to the target.")
    return audited


def _gather(mode, kind, slug, version, target, path):
    """Returns (local_path or None, origin_description)."""
    if mode in ("auto", "target"):
        listing = f"{target}wp-content/{kind}s/{slug}/"
        source = gather.gather_from_target(listing, path / "target")
        if source:
            print(f"[!] Mirrored {kind} '{slug}' source via directory listing (this is a finding!)")
            return source, "**mirrored from the target's exposed directory listing**"

    if mode in ("auto", "source"):
        source = gather.gather_from_wordpress(kind, slug, version, path / "official")
        if source:
            print(f"[*] Downloaded {kind} '{slug}' {version} from wordpress.org for local audit")
            return source, f"official wordpress.org distribution, version {version} (exact match)"

    print(f"[*] Could not gather code for {kind} '{slug}'")
    return None, None


def _report_component(report, label, origin, source, findings):
    counts = analyzer.summarize(findings)
    summary = ", ".join(f"{n} {sev}" for sev, n in sorted(counts.items(),
                                                          key=lambda kv: analyzer.SEVERITY_ORDER[kv[0]]))
    print(f"[*] Audit of {label} ({origin}): {summary or 'clean'}")

    report.paragraph(f"**{label}** - source: {origin}")
    if not findings:
        report.paragraph("No rule matched; nothing obviously dangerous in the gathered code.")
        return

    report.paragraph(f"Rules matched: {summary}. Details:")
    listed = findings[:config.MAX_REPORT_FINDINGS]
    for f in listed:
        line = (f"[{f['severity']}] **{f['rule']}** - {f['description']} "
                f"(`{f['file']}:{f['line']}`)")
        if f.get("poc", {}).get("verified"):
            line += " - **PoC VERIFIED on the target**"
        report.bullets([line])
    if len(findings) > len(listed):
        report.paragraph(f"...and {len(findings) - len(listed)} more findings of the same rules "
                         f"(see the gathered sources under the audit directory).")

    verified = [f for f in findings if f.get("poc", {}).get("verified")]
    if verified:
        report.paragraph("**Reproduced live on the target** (benign payloads - these are "
                         "confirmed, not hypothetical):")
        for f in verified:
            report.bullets([
                f"**{f['rule']}** at `{f['poc']['poc']['url']}` - {f['poc']['evidence']}"
            ])

    templates = [f for f in findings
                 if f.get("poc") and f["poc"].get("poc", {}).get("params")][:config.MAX_POC_TEMPLATES]
    if templates:
        report.paragraph("Sample PoC commands (full pack on disk; review before sending):")
        report.code("\n".join(
            f"{poc.render_curl(f['poc']['poc'])}    # {f['rule']}" for f in templates))

    critical = [f for f in findings if analyzer.SEVERITY_ORDER[f["severity"]] <= 1]
    if critical:
        report.paragraph("Evidence for the high-severity matches:")
        report.code("\n".join(
            f"{f['file']}:{f['line']} [{f['severity']}/{f['rule']}]\n    {f['snippet']}"
            for f in critical))
