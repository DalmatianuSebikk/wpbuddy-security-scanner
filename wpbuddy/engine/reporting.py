"""Report finalization writers, shared by the engine and kept CLI-free.

These were private `cli.py` helpers. Moving them next to the engine keeps the
finalize stage testable and lets a future TUI export the same sections.
"""

import json
from pathlib import Path

from .. import risk
from ..report import Report


def suppressed(risk_item, patterns):
    """True when a finding matches a --suppressions pattern."""
    if not patterns:
        return False
    haystack = f"{risk_item.get('component')}:{risk_item.get('name') or ''}".lower()
    return any(pattern.lower() in haystack for pattern in patterns)


def severity_band(severity):
    """'critical'|'high'|'medium'|'low' from a severity string or CVSS number."""
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


BAND_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def write_priorities(report, model, suppressions=()):
    """The Remediation priorities section: what to fix first."""
    creds = model.credentials()
    risks = [r for r in model.risks() if not suppressed(r, suppressions)]
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


def write_exec_summary(report, model, metadata):
    """The executive summary, spliced in right under the title."""
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
        band = severity_band(item.get("severity")) or "unknown"
        bands[band] = bands.get(band, 0) + 1
    creds = model.credentials()

    summary.paragraph(f"Components discovered: {comp_text}. Vulnerability findings: "
                     f"{len(risks)}"
                     + (" (" + ", ".join(f"{n} {band}" for band, n in sorted(
                         bands.items(), key=lambda kv: BAND_ORDER.get(kv[0], 9))) + ")"
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


def write_diff_section(report, model, previous_json_path, target):
    """What changed since the graph in previous_json_path."""
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

    def vuln_set(nodes, source):
        out = set()
        for edge in (previous.get("edges") if source is prev_nodes else current["edges"]):
            if edge.get("relation") != "affected-by":
                continue
            label = nodes.get(edge["to"], {}).get("label", "?")
            out.add((edge["from"], label))
        return out

    prev_vulns, curr_vulns = vuln_set(prev_nodes, prev_nodes), vuln_set(curr_nodes, curr_nodes)

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


def fail_on_check(model, fail_on, suppressions):
    """The --fail-on gate: returns a reason string or None."""
    if fail_on == "none":
        return None
    risks = [r for r in model.risks() if not suppressed(r, suppressions)]
    if fail_on == "any":
        if model.credentials():
            return "working credentials were found"
        if risks:
            return f"{len(risks)} vulnerability finding(s)"
        return None
    threshold = BAND_ORDER[fail_on]
    for item in risks:
        band = severity_band(item.get("severity")) or "low"
        if BAND_ORDER[band] <= threshold:
            return (f"{item['component']}: {item['name']} "
                    f"(severity {item.get('severity') or 'unrated'})")
    return None
