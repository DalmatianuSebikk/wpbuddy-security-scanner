"""Confidence model: evidence weights, scoring heuristics and the per-scan graph.

A finding is only as good as its weakest evidence link. "Plugin X 1.2.3 is
affected by CVE-Y" chains three separate claims:

  presence     - how do we know the component exists at all?
                 (readme readable on target > enumeration > fingerprint >
                  page reference > operator-supplied slug)
  version      - which artifact gave the number?
                 (explicit 'Stable tag:'/'Version' line > theme style.css >
                  first number near a changelog anchor)
  applicability- did the advisory really bound the affected versions?
                 (explicit range matched > 'unfixed' flag > no data: assumed)

This module centralizes the weights so the report can label every finding
with an earned tier instead of presenting everything as fact, and resolves
multiple evidence sources (agreement = corroboration, disagreement = a
discrepancy the operator must know about - stale caches and fake readmes
look exactly like that).

ScanModel collects the same facts as a JSON-serializable graph of the
scanned site (components, versions, evidence, vulnerabilities).
"""

import json

TIERS = ("CONFIRMED", "LIKELY", "UNVERIFIED", "ASSUMED")
_TIER_MIN_SCORE = {"CONFIRMED": 80, "LIKELY": 55, "UNVERIFIED": 20}

# A scanner is never 100% sure: something unprobed can always differ.
MIN_SCORE, MAX_SCORE = 5, 98

# Strongest presence source counts fully; each additional INDEPENDENT source
# adds a corroboration bonus (capped indirectly by MAX_SCORE).
CORROBORATION_BONUS = 12

PRESENCE_WEIGHTS = {
    "enum-200": 70,       # slug enumeration got real content back
    "readme-200": 60,     # component readme readable on the target
    "error-trace": 55,    # named in a PHP stack trace on an error page
    "fingerprint": 45,    # content fingerprint (class/shortcode/cookie/REST)
    "page-reference": 25, # asset/link path in the page's own markup
    "manual-list": 10,    # operator-supplied slug, nothing seen yet
}

VERSION_WEIGHTS = {
    "stable-tag": 25,       # explicit 'Stable tag:' / 'version X' line
    "style-css": 20,        # theme stylesheet 'Version:' header
    "changelog-anchor": 8,  # first bare number near a changelog/features anchor
}

OPERATOR_WEIGHTS = {
    "bounded": 12,    # explicit min/max range matched the installed version
    "unfixed": 6,     # advisory states: affects every version
    "assumed": -20,   # no range recorded - applicability defaulted to 'affected'
    # the advisory's own title bounds the issue BELOW the installed version
    # ("<= 7.5.0" while the site runs 7.5.5) while the API flag claims
    # unfixed/assumed: stale upstream data, site very likely patched. Kept
    # for review, demoted hard.
    "contradicted": -55,
    # NVD's explicit CPE range excludes the installed version: strongest
    # negative signal available, still kept in the report for review.
    "refuted": -70,
}

CORE_WEIGHTS = {
    "meta-generator": 62,  # the site describes itself
    "core-css-ver": 58,    # ?ver= on a core-enqueued stylesheet
    "rss-generator": 52,   # feed <generator> tag
    "readme-html": 48,     # readme.html leak (can be stale on patched sites)
}


def tier_for(score):
    """Score (0-100) -> tier name; the lowest tier has no minimum."""
    for tier in TIERS:
        minimum = _TIER_MIN_SCORE.get(tier)
        if minimum is not None and score >= minimum:
            return tier
    return "ASSUMED"


def score(presence_sources, version_kind=None, operator_basis=None):
    """Combine evidence weights into one confidence score (MIN_SCORE..MAX_SCORE).

    presence_sources: iterable of PRESENCE_WEIGHTS keys found for the component.
    version_kind / operator_basis: None when that link carries no evidence.
    """
    weights = sorted((PRESENCE_WEIGHTS.get(s, 15) for s in presence_sources),
                     reverse=True)
    total = (weights[0] + CORROBORATION_BONUS * (len(weights) - 1)) if weights else 0
    total += VERSION_WEIGHTS.get(version_kind or "", 0)
    total += OPERATOR_WEIGHTS.get(operator_basis or "", 0)
    return max(MIN_SCORE, min(MAX_SCORE, total))


def label(tier_or_score):
    """Render a tier label for report lines: '**[CONFIRMED]**'."""
    tier = tier_or_score if tier_or_score in TIERS else tier_for(tier_or_score)
    return f"**[{tier}]**"


def resolve_core(found):
    """Resolve all core-version detections into one answer with a confidence.

    `found` is [(version, source_key, human_source), ...] in priority order
    (core_version.discover_core_version). Sources agreeing corroborate each
    other; disagreeing values are a discrepancy (stale cache, fake readme) -
    the first value in priority order is used, but flagged and demoted.
    Returns None when no source produced a version, else a dict with
    version / values / sources / score / discrepancy.
    """
    if not found:
        return None
    values = []
    for version, _, _ in found:
        if version not in values:
            values.append(version)
    version = values[0]

    if len(values) > 1:
        return {"version": version, "values": values, "sources": found,
                "score": 25, "discrepancy": True}

    best = max(CORE_WEIGHTS.get(key, 40) for _, key, _ in found)
    total = min(MAX_SCORE, best + CORROBORATION_BONUS * (len(found) - 1))
    return {"version": version, "values": [version], "sources": found,
            "score": total, "discrepancy": False}


class ScanModel:
    """The per-scan knowledge graph: components, their evidence, vulnerabilities.

    Nodes are components and vulnerabilities; edges are 'site runs component'
    and 'component affected-by vulnerability'. Evidence (presence sources,
    version provenance) lives on the component nodes. write_json() turns the
    scan into a machine-readable graph artifact for later tooling.
    """

    def __init__(self):
        self._nodes = {}
        self._edges = []

    def add_component(self, kind, slug, version=None, version_kind=None,
                      presence=(), conf=None):
        """Upsert a component node; repeated calls merge evidence."""
        node_id = f"{kind}:{slug}"
        node = self._nodes.setdefault(node_id, {
            "id": node_id, "type": kind, "label": slug, "presence": [],
        })
        for source in presence:
            if source not in node["presence"]:
                node["presence"].append(source)
        if version:
            node["version"] = version
            node["version_source"] = version_kind
        if conf is not None:
            node["confidence"] = conf
        return node_id

    def add_vulnerability(self, component_id, vuln, conf=None):
        """A vulnerability node plus an affected-by edge from the component."""
        count = sum(1 for n in self._nodes.values() if n["type"] == "vulnerability")
        node_id = f"vuln:{component_id}:{count}"
        self._nodes[node_id] = {
            "id": node_id, "type": "vulnerability", "label": vuln.get("name", "Unnamed"),
            "severity": vuln.get("severity"), "link": vuln.get("link"),
            "applicability": vuln.get("basis"),
        }
        if conf is not None:
            conf = dict(conf)
            if "tier" not in conf and "score" in conf:
                conf["tier"] = tier_for(conf["score"])
            self._nodes[node_id]["confidence"] = conf
        self._edges.append({"from": component_id, "to": node_id,
                            "relation": "affected-by"})
        return node_id

    def components(self):
        return [n for n in self._nodes.values() if n["type"] != "vulnerability"]

    def to_dict(self, target):
        return {
            "target": target,
            "nodes": list(self._nodes.values()),
            "edges": [{"from": "site", "to": n["id"], "relation": "runs"}
                      for n in self.components()] + self._edges,
        }

    def write_json(self, path, target):
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.to_dict(target), f, indent=2)
