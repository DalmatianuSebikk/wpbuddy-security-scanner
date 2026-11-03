# F-2 — Risk scoring

**Goal:** one comparable number per finding so the report answers "what do I
fix first" instead of listing everything chronologically.

## Formula (v1, implemented)

```
risk = CVSS(0-10) x 10            # severity, unknown severity assumed 5.0
       x exposure multiplier      # unauthenticated 1.0, authenticated 0.65,
                                 # unknown 0.8
       x confidence multiplier   # max(confidence score, 30) / 100
```

- **Exposure** is parsed from the advisory text (`unauthenticated` /
  `authenticated|author+|administrator`) at `add_vulnerability` time and
  stored on the vulnerability node.
- **Confidence** reuses the existing P0/P1 applicability work (bounded vs
  assumed vs refuted already flows into the score) — refuted findings sink,
  confirmed unauth criticals float.
- **Patch availability** (a fix exists upstream when the advisory bounds the
  issue below the installed version) is shown per item, not multiplied in:
  it changes urgency, not likelihood.

`ScanModel.risks()` returns all vulnerability findings decorated with the
score, sorted descending; the report renders the top as "Remediation
priorities" (credentials first — a working password outranks everything).

## Deferred

CVSS vector parsing (only the base score arrives from the sources today),
asset-weighting (internet-facing vs staging), and reading patch availability
from feeds.
