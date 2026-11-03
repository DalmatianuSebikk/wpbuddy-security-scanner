"""Passive phase: GET-only reconnaissance and vulnerability lookups.

Everything here looks like normal browsing traffic (no POSTs, no probes that
alter state). Returns the discovered components so later phases (active,
code audit) can build on them.

Plugin discovery layers, most to least stealthy:
1. asset URLs (wp-content/plugins/...) across crawled pages
2. content fingerprints (shortcodes, body classes, JS globals, cookies,
   headers, REST namespaces) - catches plugins hidden from page sources
3. the user's manual list
4. optional slug brute-force (--enum-plugins; invasive, off by default)

Every discovery and every version is fed through the confidence layer
(wpbuddy.confidence): presence sources are combined into a score and a tier
(CONFIRMED / LIKELY / UNVERIFIED / ASSUMED) that the report shows next to
each finding, and the same facts populate the per-scan model (the knowledge
graph exported with --json).
"""

from .. import confidence, config, vulndb
from . import assets, content, core_version, dangling, files, fingerprints, posture, readme, wprest


def run(report, target, args, model=None):
    """Run the full passive phase. Returns {'plugins': {slug: ver}, 'themes': {slug: ver}}."""
    if model is None:
        model = confidence.ScanModel()
    results = {"plugins": {}, "themes": {}}

    namespaces = wprest.discover_rest_namespaces(target)
    # one crawl shared by every consumer (plugin refs, fingerprints, dangling DNS)
    pages = content.crawl_page_urls(target, args.max_pages)
    refs, artifacts = content.discover_refs(pages, target)
    # ?ver= parameters on component assets (F-5): version source of last
    # resort when no readme is readable
    from urllib.parse import urlparse as _urlparse
    versions_from_assets = assets.asset_versions(artifacts.get("pages_html", ""),
                                                 (_urlparse(target).hostname or "").lower())

    _scan_core(report, target, model)
    results["plugins"] = _scan_plugins(report, target, args, namespaces, model, pages,
                                       refs, artifacts, versions_from_assets)
    results["themes"] = _scan_themes(report, target, model, refs, versions_from_assets)
    _scan_rest(report, target, namespaces)
    files.check_robots(report, target)
    files.check_security_txt(report, target)
    files.check_sensitive_files(report, target)
    files.check_setup_wizard(report, target)
    files.check_headers(report, target)
    dangling.check(report, target, artifacts.get("pages_html", ""))
    posture.check(report, target)
    from . import extrachecks  # F-9: wp-cron, install pages, CORS, cookies
    extrachecks.run(report, target)
    if config.AUTH_COOKIE or config.AUTH_BASIC:
        from . import authcheck  # deferred: only imported when creds exist
        authcheck.check(report, target)
    return results


def _scan_core(report, target, model):
    report.section("WordPress core version")
    resolved = confidence.resolve_core(core_version.discover_core_version(target))
    if not resolved:
        print("[!] WordPress core version could not be identified passively")
        report.paragraph("WordPress core version could not be identified with the passive methods "
                         "(meta generator, core stylesheet ?ver=, RSS feed, readme.html).")
        return

    version = resolved["version"]
    tier = confidence.tier_for(resolved["score"])
    sources_text = ", ".join(source for _, _, source in resolved["sources"])
    print(f"[*] WordPress core version: {version} [{tier}] (from {sources_text})")
    report.paragraph(f"WordPress core version: **{version}** {confidence.label(tier)} "
                     f"(confidence {resolved['score']}/100) - discovered via {sources_text}.")

    if resolved["discrepancy"]:
        conflicting = "; ".join(f"**{v}** from the {s}"
                                for v, _, s in resolved["sources"] if v != version)
        print(f"[!] Version sources disagree ({conflicting}); using {version}")
        report.paragraph(f"**Version sources disagree:** {conflicting}; the value in use is "
                         f"**{version}** (highest-priority source, demoted to {tier}). Stale "
                         f"page caches and unpatched readme.html files look exactly like this - "
                         f"treat core findings accordingly.")

    model.add_component("core", "wordpress", version,
                        version_kind=resolved["sources"][0][1],
                        presence=[key for _, key, _ in resolved["sources"]],
                        conf={"score": resolved["score"], "tier": tier})

    report.paragraph("Vulnerabilities known to affect this core version "
                     "(includes issues fixed in later releases - the site is only patched by updating):")

    vulns, status = vulndb.core_lookup(version)
    if status != "ok":
        print("[!] Core vulnerability lookup failed - vulnerability database unreachable")
        report.paragraph("**Vulnerability lookup failed** - the wpvulnerability.net database "
                         "was unreachable, so this section says nothing about the site's real "
                         "exposure. Re-run the scan before trusting a 'clean' verdict here.")
        return
    vulns = vulndb.affected_vulnerabilities(version, vulns)
    vulns = vulndb.enrich_core_with_nvd(version, vulns)
    if not vulns:
        report.paragraph("No known vulnerabilities in the wpvulnerability.net database for this version.")
        return
    print(f"[!] {len(vulns)} core vulnerabilities reported for {version}")
    core_presence = [key for _, key, _ in resolved["sources"]]
    report.bullets([_format_vuln(v, _vuln_tier(core_presence, v)) for v in vulns])
    for v in vulns:
        model.add_vulnerability("core:wordpress", v, conf={
            "score": confidence.score(core_presence, operator_basis=v.get("basis"))})
    report.paragraph("**Recommendation:** update WordPress core to the latest release.")


def _vuln_tier(presence, vuln, version_kind=None):
    """Confidence label of one vulnerability finding.

    Chains the component's presence evidence, its version provenance and the
    advisory's applicability basis ('assumed' findings score lower).
    """
    value = confidence.score(presence, version_kind=version_kind,
                             operator_basis=vuln.get("basis"))
    return confidence.label(value)


def _scan_plugins(report, target, args, namespaces, model, pages, refs, artifacts,
                  asset_versions_map=None):
    report.section("Plugins")
    manual = config.load_lines(args.pluginList) if args.pluginList else []
    fingerprinted = fingerprints.detect(artifacts, namespaces)
    discovered = refs["plugins"]

    if refs["plugins"]:
        print(f"[*] Same-site plugin references: {', '.join(sorted(refs['plugins']))}")
    report.paragraph(f"Plugin references found in {len(pages)} crawled page(s) "
                     f"(same-site links/assets/inline scripts only; third-party wp-content "
                     f"URLs are ignored as false positives): "
                     + (", ".join(f"**{p}**" for p in sorted(refs["plugins"])) or "none"))

    if fingerprinted:
        print(f"[*] Plugins matched by content fingerprints: {', '.join(sorted(fingerprinted))}")
        report.paragraph("Plugins identified by content fingerprinting (shortcodes, body classes, "
                         "JS globals, cookies or REST namespaces - these leave no URL traces):")
        report.bullets([f"**{p}** (matched via {fingerprints.explain(p)})"
                        for p in sorted(fingerprinted)])

    enum_installed = []
    if getattr(args, "enum_plugins", False):
        from ..active import enumerate as slug_enum  # deferred: avoids import cycle
        slugs = slug_enum.fetch_popular_slugs(getattr(args, "enum_limit", config.DEFAULT_ENUM_LIMIT))
        if slugs:
            enum_installed = slug_enum.enumerate_plugins(report, target, slugs)
            discovered |= set(enum_installed)
        else:
            print("[!] Could not fetch the popular-plugin list from wordpress.org")

    if manual:
        print(f"[*] Extra plugins from the manual list: {', '.join(manual)}")

    # Evidence per slug: every layer that pointed at it becomes a presence
    # source, combined into a confidence score/tier by wpbuddy.confidence.
    presence = {}
    for slug in discovered:
        presence.setdefault(slug, []).append("page-reference")
    for slug in fingerprinted:
        presence.setdefault(slug, []).append("fingerprint")
    for slug in enum_installed:
        presence.setdefault(slug, []).append("enum-200")
    for slug in manual:
        presence.setdefault(slug, []).append("manual-list")

    versions, version_kinds = {}, {}
    for slug in sorted(presence):
        version, src, kind = readme.find_component_version(target, "plugins", slug)
        if not version and asset_versions_map:
            # no readable readme: the plugin's own enqueued assets still
            # carry its version in ?ver= (F-5)
            version = asset_versions_map.get(("plugins", slug))
            if version:
                kind = "asset-ver"
                print(f"[*] Plugin {slug}: version {version} (asset ?ver=)")
        versions[slug] = version
        version_kinds[slug] = kind
        comp_score = confidence.score(presence[slug], version_kind=kind)
        tier = confidence.tier_for(comp_score)
        model.add_component("plugin", slug, version, kind, presence[slug],
                            conf={"score": comp_score, "tier": tier})
        if version:
            print(f"[*] Plugin {slug}: version {version} ({kind}) [{tier}]")

    # A readable readme.txt on the TARGET is proof of installation; a bare page
    # reference is not. Report provenance honestly instead of one big list.
    confirmed_no_version = (set(enum_installed) | fingerprinted) - {s for s, v in versions.items() if v}
    unverified = [s for s, v in versions.items()
                  if not v and s not in confirmed_no_version and s in refs["plugins"]]

    report.section("Plugin vulnerability analysis (wpvulnerability.net)")
    clean = []
    for slug, version in versions.items():
        if not version:
            continue
        tier = confidence.tier_for(
            confidence.score(presence[slug], version_kind=version_kinds[slug]))
        vulns, status = vulndb.plugin_lookup(slug)
        if status != "ok":
            report.paragraph(f"**{slug}** {version} {confidence.label(tier)} - vulnerability "
                             f"**lookup failed** (database unreachable); applicability unknown. "
                             f"Do not read this as 'no vulnerabilities'.")
            continue
        if vulns is None:
            report.paragraph(f"**{slug}** {version} {confidence.label(tier)} (version from "
                             f"the target's readme.txt) - not present in the vulnerability "
                             f"database (not a wordpress.org slug or simply unresearched).")
            continue
        affected = vulndb.affected_vulnerabilities(version, vulns, slug=slug)
        if not affected:
            clean.append(f"**{slug}** {version}")
            continue
        print(f"[!] {len(affected)} vulnerabilities affect {slug} {version}")
        report.paragraph(f"**{slug}** {version} {confidence.label(tier)} is affected by:")
        report.bullets([_format_vuln(v, _vuln_tier(presence[slug], v, version_kinds[slug]))
                        for v in affected])
        for v in affected:
            model.add_vulnerability(f"plugin:{slug}", v, conf={
                "score": confidence.score(presence[slug], version_kind=version_kinds[slug],
                                          operator_basis=v.get("basis"))})
        report.paragraph(f"**Recommendation:** update **{slug}** to its latest version.")

    if clean:
        report.paragraph("No known vulnerabilities affect these versions (each version "
                         "read from the component's own readme.txt on the target): "
                         + ", ".join(sorted(clean)) + ".")

    if confirmed_no_version:
        report.paragraph("Present on the target but version unknown "
                         + "(presence confirmed by enumeration or fingerprint; readme files not "
                           "readable; CVE matching impossible without a version): "
                         + ", ".join(f"**{s}** {confidence.label(confidence.score(presence[s]))}"
                                     for s in sorted(confirmed_no_version)))
    if unverified:
        report.paragraph("Unverified references - plugins named in page sources whose readme "
                         "could not be read and which enumeration did not confirm. These may "
                         "be stale or third-party content and are NOT treated as findings: "
                         + ", ".join(f"{s}" for s in unverified))
    manual_unverified = [s for s in manual if not versions.get(s)]
    if manual_unverified:
        report.paragraph("User-supplied slugs that could not be confirmed on the target "
                         "(readme not readable): " + ", ".join(f"{s}" for s in manual_unverified))
    return versions


def _scan_themes(report, target, model, refs=None, asset_versions_map=None):
    """Theme discovery over the SAME crawled pages the plugin scan used.

    Themes used to be scraped from the homepage alone (a second fetch!) -
    a child theme referenced only on an inner page was invisible (P1-8).
    `refs` is the refs dict from run()'s crawl; standalone callers without
    one get the old homepage-only behaviour. `asset_versions_map` supplies
    ?ver=-based versions when style.css is unreadable (F-5).
    """
    report.section("Theme")
    if refs is None:
        pages = [target]
        refs, _ = content.discover_refs(pages, target)
    themes = sorted(refs["themes"])
    if not themes:
        print("[!] No theme identified")
        report.paragraph("No theme could be identified in the page sources.")
        return {}

    for theme in themes:
        report.paragraph(f"Theme discovered: **{theme}** (wp-content/themes/{theme})")

    versions = {}
    for slug in themes:
        version, src, kind = readme.find_component_version(target, "themes", slug)
        if not version and asset_versions_map:
            version = asset_versions_map.get(("themes", slug))
            if version:
                src, kind = "asset ?ver= parameter in crawled pages", "asset-ver"
                print(f"[*] Theme {slug}: version {version} (asset ?ver=)")
        versions[slug] = version
        comp_score = confidence.score(["page-reference"], version_kind=kind)
        tier = confidence.tier_for(comp_score)
        model.add_component("theme", slug, version, kind, ["page-reference"],
                            conf={"score": comp_score, "tier": tier})
        if version:
            print(f"[*] Theme {slug}: version {version} ({kind}) [{tier}]")
            report.paragraph(f"Theme **{slug}** version: **{version}** {confidence.label(tier)} "
                             f"(from {src})")
            vulns, db_status = vulndb.theme_lookup(slug)
            if db_status != "ok":
                report.paragraph(f"Theme **{slug}** {version} - vulnerability **lookup "
                                 f"failed** (database unreachable); applicability unknown.")
            elif vulns is None:
                report.paragraph(f"**{slug}** - not present in the vulnerability database.")
            else:
                affected = vulndb.affected_vulnerabilities(version, vulns, slug=slug)
                if affected:
                    print(f"[!] {len(affected)} vulnerabilities affect theme {slug} {version}")
                    report.paragraph(f"Theme **{slug}** {version} is affected by:")
                    report.bullets([_format_vuln(v, _vuln_tier(["page-reference"], v, kind))
                                    for v in affected])
                    for v in affected:
                        model.add_vulnerability(f"theme:{slug}", v, conf={
                            "score": confidence.score(["page-reference"], version_kind=kind,
                                                      operator_basis=v.get("basis"))})
                else:
                    report.paragraph(f"Theme **{slug}** {version} - no known vulnerabilities affect "
                                     f"this version.")
        else:
            report.paragraph(f"Theme **{slug}** - version could not be determined.")
    return versions


def _scan_rest(report, target, namespaces):
    report.section("REST API (/wp-json/) discovery")
    if namespaces is None:
        report.paragraph("The REST API index is not readable (disabled, restricted or WAF'd).")
        return
    if namespaces:
        print(f"[*] Plugin REST namespaces exposed: {', '.join(namespaces)}")
        report.paragraph("Plugins registering their own REST routes (fingerprint via "
                         "/wp-json/): " + ", ".join(f"`{ns}`" for ns in namespaces))
    else:
        report.paragraph("REST API is enabled but exposes only core namespaces.")


def _format_vuln(v, tier_label=None):
    from ..report import _md_url, escape_md
    text = f"**{escape_md(v['name'])}**"
    if tier_label:
        text += f" {tier_label}"
    if v.get("severity"):
        text += f" (CVSS {escape_md(v['severity'])})"
    # descriptions arrive as multi-paragraph prose; one line, capped, keeps
    # the finding a bullet instead of breaking the list apart
    description = (v.get("description") or "").strip()
    if description:
        first = description.splitlines()[0].strip()
        if len(first) > 200:
            first = first[:197] + "..."
        text += f": {first}"
    basis = {"bounded": "version range matched",
             "unfixed": "listed as unfixed - affects all versions",
             "assumed": "NO version range recorded - applicability assumed",
             "contradicted": "advisory title bounds this BELOW your version - "
                             "likely already patched, kept for review",
             "refuted": "NVD version range EXCLUDES your version - likely not affected",
             }.get(v.get("basis"))
    if basis:
        text += f" ({basis})"
    # the advisory carries the actual exploitation details (vulnerable endpoint,
    # parameters, PoC steps) that a scanner cannot responsibly auto-fire
    if v.get("link"):
        text += f" ([advisory with exploitation details]({_md_url(v['link'])}))"
    return text
