# F-10 — Reporting

**Goal:** the report works for three audiences: the executive (summary
first), the tooling pipeline (diff/fail-on/suppressions), and CI.

## Implemented

- **Executive summary** spliced directly under the title
  (`Report.prepend` — markdownmaker only appends): scan metadata (target,
  version, timestamp, duration, profile flags), component/finding counts by
  severity band, credential count, and the top-3 risks inline.
- **`--diff PREV_JSON`**: compares this scan's knowledge graph with a
  previous `--json` output — new/gone components, new findings, resolved
  findings (the "did the update work" answer).
- **`--fail-on {none,critical,high,medium,any}`**: exit code 1 when an
  unsuppressed finding is at/above the band (word or CVSS-derived);
  discovered credentials always count as critical. CI-ready.
- **`--suppressions FILE`**: substring patterns (case-insensitive) matched
  against `component:name`; matches leave the priorities summary and the
  `--fail-on` gate (never silently deleted from the body of the report —
  the detailed sections stay honest).

## Deferred

HTML/PDF rendering and SARIF export (both need a template/render pipeline
decision — the graph JSON already carries everything a SARIF writer would
need).
