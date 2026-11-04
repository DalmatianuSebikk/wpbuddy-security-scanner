"""Version-string helpers: extraction and comparison."""

import re

# Matches 2+ dotted numeric groups, e.g. 6.4, 6.4.3, 1.2.3.4
VERSION_RE = re.compile(r"\d+\.\d+(?:\.\d+)*")


def extract_version(text):
    """Return the first version-looking token in text, or None."""
    if not text:
        return None
    m = VERSION_RE.search(str(text))
    return m.group() if m else None


def major_minor(version):
    """Collapse a version to its major.minor branch ('6.4.3' -> '6.4')."""
    parts = str(version).split(".")
    return ".".join(parts[:2]) if len(parts) >= 2 else str(version)


def compare_versions(a, b):
    """Compare two dotted versions: -1 if a<b, 0 if equal, 1 if a>b.

    Non-numeric segments count as 0 and missing segments are padded with 0,
    so compare_versions('6.4', '6.4.0') == 0 and ('5.10', '5.9') == 1.
    """
    def segments(v):
        return [int(p) if p.isdigit() else 0 for p in str(v or "0").split(".")]

    sa, sb = segments(a), segments(b)
    width = max(len(sa), len(sb))
    sa += [0] * (width - len(sa))
    sb += [0] * (width - len(sb))
    for x, y in zip(sa, sb):
        if x != y:
            return -1 if x < y else 1
    return 0
