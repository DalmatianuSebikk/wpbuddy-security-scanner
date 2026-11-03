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
from shutil import rmtree
from urllib.parse import urlsplit

from .. import config
from ..passive import files as passive_files  # listing finding (P1-7); no cycle
from . import analyzer, deps, gather, malware, poc, semgrep

_MODES = ("auto", "target", "source", "off")

# Marker file recording HOW a cached component tree was produced. It is only
# written after a successful gather and is what makes a cache entry trusted
# (P0-3/P1-11): without it a partial mirror or dead extraction cannot be told
# apart from a complete source, and the analyzer would walk the wrong layout.
_ORIGIN_MARKER = ".origin"


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
    unaudited = []
    source_dir = getattr(args, "source_dir", None)

    for kind, components in (("plugin", passive_results.get("plugins", {})),
                             ("theme", passive_results.get("themes", {}))):
        for slug, version in components.items():
            label = f"{kind} {slug}" + (f" {version}" if version else "")
            # cache directory includes the VERSION: a cached download of 2.1
            # must never be audited and reported as the 2.4 running now
            path = workdir / f"{kind}-{slug}-{version}" if version else \
                workdir / f"{kind}-{slug}-unknown"
            mirrored = False
            # A listing probe doubles as a finding when it succeeds (P1-7);
            # only the modes that already request listings do this, keeping
            # the --stealth contract of P0-2 intact.
            if mode in ("auto", "target"):
                passive_files.check_directory_listing(report, target, slug, f"{kind}s")
            if version and path.exists():
                source, origin, mirrored = _load_cached_source(path, version)
                if source is None:
                    # Unclassifiable cache (interrupted gather, dead
                    # extraction, pre-marker junk): never audit it and never
                    # build the fresh gather on top of its remains (P1-11).
                    rmtree(path, ignore_errors=True)
            else:
                source, origin = None, None
            if source is None:
                source, origin, reason = _gather(mode, kind, slug, version, target, path,
                                                 source_dir=source_dir)
                if source is None:
                    if reason:
                        unaudited.append((label, reason))
                    continue
                mirrored = "mirrored" in origin
                _mark_cache_origin(path, "mirrored" if mirrored else "official")
            findings = analyzer.analyze(source)
            # malware/webshell/secret findings render in the same component
            # list (F-7); they are findings about the code itself
            findings += malware.scan(source)
            if getattr(args, "semgrep", False):
                extra = semgrep.scan(source)
                if extra:
                    findings += extra
            findings.sort(key=lambda f: (analyzer.SEVERITY_ORDER[f["severity"]],
                                         f["file"], f["line"]))
            if getattr(args, "verify_pocs", False) and findings:
                findings = poc.verify_findings(report, target, kind, findings, mirrored)
            if mirrored and version:
                _integrity_check(report, label, kind, slug, version, path)
            inventory, dep_advisories = deps.scan(source)
            deps.report_dependencies(report, label, inventory, dep_advisories)
            _report_component(report, label, origin, source, findings)
            audited[slug] = findings
            pack_entries += [
                (label, f, f["poc"]["poc"])
                for f in findings
                if f.get("poc") and f["poc"].get("poc", {}).get("params")
            ]

    # Unaudited components are reported even when NOTHING could be gathered:
    # silently dropping them (the old early return) hid both the component
    # and the reason it was skipped (P1-6).
    if unaudited:
        report.paragraph("Components the audit could NOT gather, and why:")
        report.bullets([f"**{label}** - {_reason_text(reason)}"
                        for label, reason in unaudited])
        report.paragraph("Provide a licensed copy as `<kind>-<slug>-<version>.zip` via "
                         "`--source-dir DIR` to audit anything in the first two buckets.")

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


def _integrity_check(report, label, kind, slug, version, path):
    """Modified-file detection (F-4): deployed mirror vs official archive.

    Compares the mirrored production code with the official wordpress.org
    distribution of the exact same version (fetched once into the same
    cache entry; no extra target requests). Modified or added files are how
    backdoors and nulled-plugin phones home survive updates.
    """
    official_root = path / "official"
    if not official_root.is_dir():
        fetched = gather.gather_from_wordpress(kind, slug, version, official_root)
        if not fetched or not fetched[0]:
            return  # no official copy obtainable (commercial/custom) - nothing to diff
        print(f"[*] Integrity: fetched official {kind} '{slug}' {version} for comparison")
    base = official_root / slug
    base = base if base.is_dir() else official_root
    modified, added = _diff_trees(path / "target", base, kind, slug)
    if modified or added:
        print(f"[!] Integrity: {label} differs from the official distribution "
              f"({len(modified)} modified, {len(added)} added)")
        report.paragraph(f"**{label}: deployed code DIFFERS from the official "
                         f"distribution** - {len(modified)} modified, {len(added)} added "
                         f"file(s). Modified component files are how backdoors survive "
                         f"updates; review every file listed:")
        report.bullets([f"modified: `{rel}`" for rel in sorted(modified)[:15]]
                       + [f"added (not in the official {version} archive): `{rel}`"
                          for rel in sorted(added)[:15]])
    else:
        report.paragraph(f"{label}: mirrored files match the official {version} "
                         f"distribution byte-for-byte - no tampering visible in "
                         f"the mirrored set.")


def _diff_trees(mirror_root, official_root, kind, slug, max_files=2000):
    """(modified, added) relative paths between a deployed mirror and the
    official archive. Only text-type files are compared - the mirror skips
    binaries by design, so they would all read as 'removed'.
    Paths normalize to the component root: mirror files live under
    wp-content/<kind>s/<slug>/..., official ones under <slug>/....
    """
    import hashlib

    def scan(root, strip):
        out = {}
        root = Path(root)
        if not root.is_dir():
            return out
        for p in sorted(root.rglob("*"))[:max_files]:
            if not p.is_file() or p.suffix.lower() not in gather.DOWNLOAD_EXTENSIONS:
                continue
            if p.stat().st_size > config.MAX_AUDIT_FILE_SIZE:
                continue
            rel = p.relative_to(root).as_posix()
            if strip and rel.startswith(strip):
                rel = rel[len(strip):]
            out[rel] = hashlib.sha256(p.read_bytes()).hexdigest()
        return out

    mirror = scan(mirror_root, f"wp-content/{kind}s/{slug}/")
    official = scan(official_root, f"{slug}/")
    modified = [rel for rel, digest in mirror.items()
                if rel in official and official[rel] != digest]
    added = [rel for rel in mirror if rel not in official]
    return modified, added


def _load_cached_source(path, version):
    """(source_dir, origin, mirrored) for a complete cached component tree.

    Mirrors are analyzed from their `target/` subtree so finding paths start
    at wp-content/... exactly like a fresh mirror (the double
    wp-content/plugins/target/... PoC prefix of the old cache handling came
    from walking the cache root instead). Returns (None, None, False) for a
    cache we cannot classify - the caller re-gathers (P1-11).
    """
    how = _cache_kind(path)
    if how == "mirrored":
        return (path / "target",
                f"**cached mirror** of the target's exposed listing (previous scan, {version})",
                True)
    if how == "official":
        return (path / "official",
                f"cached official source from a previous scan ({version})", False)
    return None, None, False


def _cache_kind(path):
    """'mirrored', 'official' or None for a cache directory.

    The .origin marker is authoritative (written only after a successful
    gather). Marker-less caches predate it: a `target/` subtree can only be
    a mirror, anything else is not trusted and re-gathered.
    """
    marker = path / _ORIGIN_MARKER
    if marker.is_file():
        how = marker.read_text(encoding="utf-8", errors="replace").strip().lower()
        return how if how in ("mirrored", "official") else None
    if (path / "target").is_dir():
        return "mirrored"
    return None


def _mark_cache_origin(path, how):
    """Record how this cache entry was produced - after a successful gather."""
    try:
        (path / _ORIGIN_MARKER).write_text(how + "\n", encoding="utf-8")
    except OSError as e:
        print(f"[!] Could not mark audit cache {path}: {e}")


def _gather(mode, kind, slug, version, target, path, source_dir=None):
    """Returns (local_path or None, origin or None, failure_reason or None)."""
    if mode in ("auto", "target"):
        listing = f"{target}wp-content/{kind}s/{slug}/"
        source = gather.gather_from_target(listing, path / "target")
        if source:
            print(f"[!] Mirrored {kind} '{slug}' source via directory listing (this is a finding!)")
            return source, "**mirrored from the target's exposed directory listing**", None
        if mode == "target":
            # Listing-only mode failed. An operator-provided archive is still
            # legitimate (it never touches the target), but wordpress.org
            # stays off-limits by the target-mode contract (P1-6).
            if source_dir:
                source, origin, _ = gather.gather_from_wordpress(
                    kind, slug, version, path / "official",
                    source_dir=source_dir, operator_only=True)
                if source:
                    print(f"[*] Gathered {kind} '{slug}' {version}: {origin}")
                    return source, origin, None
            return None, None, "no-listing"

    if mode in ("auto", "source"):
        source, origin, reason = gather.gather_from_wordpress(
            kind, slug, version, path / "official", source_dir=source_dir)
        if source:
            print(f"[*] Gathered {kind} '{slug}' {version}: {origin}")
            return source, origin, None
        print(f"[*] Could not gather {kind} '{slug}' {version}: {reason}")
        return None, None, reason
    return None, None, None


_GATHER_REASONS = {
    "no-version": "version unknown (readme not readable) - no exact code to fetch",
    "not-hosted": "not distributed on wordpress.org - a commercial or custom "
                  "component; licensed copies are the only legitimate source",
    "version-not-published": "wordpress.org hosts it, but not this exact version "
                             "(older releases are pruned from the directory)",
    "download-failed": "download failed (network or CDN error)",
    "bad-archive": "the downloaded archive could not be extracted",
    "no-listing": "no exposed directory listing on the target, and target mode "
                  "gathers nothing else - pass a licensed archive via "
                  "--source-dir DIR, or use --audit-code auto/source for "
                  "wordpress.org downloads",
    "no-operator-archive": "no matching archive in --source-dir for this exact "
                           "component and version",
}


def _reason_text(reason):
    return _GATHER_REASONS.get(reason, reason or "unknown")


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
    # HIGH and above are listed with evidence; LOW/INFO are review-only noise
    # (autoloader patterns, interpolation reviews) and would bury them - a
    # count line plus the grep-able sources on disk is the honest summary.
    notable_severities = ("CRITICAL", "HIGH", "MEDIUM")
    notable = [f for f in findings if f["severity"] in notable_severities]
    listed = notable[:config.MAX_REPORT_FINDINGS]
    for f in listed:
        line = (f"[{f['severity']}] **{f['rule']}** - {f['description']} "
                f"(`{f['file']}:{f['line']}`)")
        if f.get("poc", {}).get("verified"):
            line += " - **PoC VERIFIED on the target**"
        report.bullets([line])
    if len(notable) > len(listed):
        report.paragraph(f"...and {len(notable) - len(listed)} more notable findings "
                         f"(see the gathered sources under the audit directory).")
    review_only = len(findings) - len(notable)
    if review_only:
        report.paragraph(f"{review_only} LOW/INFO review-only matches omitted from this "
                         f"list - grep them in `{source}` under the audit directory.")

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
