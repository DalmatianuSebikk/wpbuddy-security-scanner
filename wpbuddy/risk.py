"""Risk scoring: one comparable number per finding (F-2).

CVSS says how bad a bug is in the abstract; it does not say what it means
for THIS site right now. Risk here is severity, scaled by how reachable the
bug is (unauthenticated beats administrator-only) and by how sure the
scanner is the site actually has it (the P0/P1 applicability work feeds the
confidence score). The output orders the "Remediation priorities" section.

Design note: docs/design/F-02-risk-scoring.md
"""

import re

# no advisory text to tell us who can reach it - assume the middle
EXPOSURE_MULTIPLIERS = {"unauthenticated": 1.0, "authenticated": 0.65, "unknown": 0.8}

_AUTHENTICATED_RE = re.compile(
    r"authenticated|subscriber|contributor|author\b|editor\b|administrator|"
    r"admin[- ]only|privilege|capability|logged[- ]in", re.I)
_UNAUTHENTICATED_RE = re.compile(r"unauthenticated|unauth\b|any (?:visitor|user)|guest", re.I)


def parse_cvss(severity):
    """Numeric CVSS score from strings like '7.5 (high)' / '7.5'. None if absent."""
    if not severity:
        return None
    match = re.search(r"\d+(?:\.\d+)?", str(severity))
    try:
        value = float(match.group()) if match else None
    except ValueError:
        return None
    return value if value is not None and 0.0 <= value <= 10.0 else None


def exposure(description):
    """('unauthenticated'|'authenticated'|'unknown', multiplier) for advisory text."""
    text = description or ""
    if _UNAUTHENTICATED_RE.search(text):
        return "unauthenticated", EXPOSURE_MULTIPLIERS["unauthenticated"]
    if _AUTHENTICATED_RE.search(text):
        return "authenticated", EXPOSURE_MULTIPLIERS["authenticated"]
    return "unknown", EXPOSURE_MULTIPLIERS["unknown"]


def patch_available(applicability):
    """True when the advisory itself bounds the issue below the installed
    version - a fixed release exists upstream."""
    return applicability in ("bounded", "contradicted", "refuted")


def risk_score(severity, exposure_label, confidence_score=None):
    """0-100 comparable risk for one finding."""
    cvss = parse_cvss(severity)
    base = cvss if cvss is not None else 5.0
    mult = EXPOSURE_MULTIPLIERS.get(exposure_label, EXPOSURE_MULTIPLIERS["unknown"])
    conf = 50.0 if confidence_score is None else float(confidence_score)
    # uncertain findings still rank, but a confident equal-CVSS finding wins
    score = base * 10 * mult * (max(conf, 30.0) / 100.0)
    return round(min(100.0, score), 1)
