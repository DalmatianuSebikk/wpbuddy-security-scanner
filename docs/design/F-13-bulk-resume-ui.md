# F-13 — Bulk inventory / resume / schedule + read-only UI — NOT STARTED

**Status: design note only.** Do not implement before the exploitation
roadmap's engagement model (`Engagement` → `Run` persistence) exists —
everything below is persistence-layer work on top of it.

## Shape of the eventual design

- **Bulk inventory**: a `targets.txt` (or `--targets-file`) of base URLs;
  one `Engagement` per target, per-target rate budgets, shared caches
  (vuln DB, downloads). Failure isolation: one dead target must not cost
  the others their reports.
- **Resume**: every scan writes its run state (the knowledge graph plus
  phase progress) as the single resumable artifact; `--resume run.json`
  re-enters at the first incomplete phase. This requires phases to be
  idempotent against the graph — currently true for the passive/audit
  phases, not for the active one.
- **Schedule**: deliberately NOT a daemon in v1 — a cron/systemd example
  + `--diff` (F-10) already covers "scan nightly and tell me what
  changed" without the scanner holding privileges while idle.
- **Read-only web UI/TUI**: renders the knowledge graph JSON (components,
  findings, risk ordering, trends across runs via `--diff`). Read-only
  means no scan control surface — the launcher keeps authorization.

## Prerequisites

Engagement model + injectable HTTP client per target (roadmap items 3-4),
so concurrent targets stop sharing module globals (config.TARGET_HOST,
httpclient.SESSION, the passive collectors' state).
