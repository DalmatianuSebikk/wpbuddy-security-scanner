# WpBuddy TUI — stable runs folder + launcher (delta design)

Date: 2026-11-04
Status: approved (partner amendment: `~/.wpbuddy/previous-runs`; credential-test
revamp explicitly parked for later)

## Intent

Two partner requests on top of the shipped flow observatory:

1. **Runs accumulate in one stable folder.** Today the run store writes
   `wpbuddy-audit/<host>/runs/` relative to the process CWD — a scan launched
   from a temp/parking directory strands its history there. Runs (timeline,
   engagement, events, artifacts) must land in one findable place regardless
   of CWD.
2. **`wpbuddy flow` without a target opens a launcher.** Pick/enter a target,
   choose what the run should do (functionality checkboxes mapped 1:1 to CLI
   flags), optionally open a previous run, then launch into the existing
   single-screen observatory.

## Decisions

- **Runs root default: `~/.wpbuddy/previous-runs/`** — the tool's home
  directory (already home to `vulndb.sqlite3`), preserving the per-host
  grouping: `~/.wpbuddy/previous-runs/<host>/<run_id>/{meta,engagement,
  events.jsonl,artifacts}`. Override: `--runs-dir DIR` (scan and flow) and
  `config.RUNS_DIR`. `None` means legacy CWD-relative `wpbuddy-audit/...` —
  which is what the test suite pins via conftest, so existing tests keep
  their layout unchanged.
- **Unchanged on purpose:** report outputs (`outputScan.md`/`.json`) stay
  CWD-relative (operator names them), and the code-audit cache
  (`wpbuddy-audit/<host>/plugin-...`) stays CWD-relative — only the RUN
  STORE moves. Documented in the report's audit-dir paragraph? No: the
  report text that mentions `wpbuddy-audit` for gathered sources remains
  accurate; run paths printed to console now point at the runs root.
- **Launcher is sugar over the canonical CLI.** Checkboxes map 1:1 to flags:
  deep discovery → `--profile deep`; slug enumeration → `--enum-plugins`;
  credential test → `--access` (current shape only — revamp parked);
  code audit mode → cycle `off/source/target/auto` → `--audit-code`;
  verify PoCs → `--verify-pocs`; JSON graph → `--json`; failure gate →
  cycle `none/critical/high/medium/any` → `--fail-on`. `c` copies the exact
  command; Launch spawns the same `wpbuddy scan` subprocess and drops into
  the observatory (no second orchestration path).
- **Previous-runs browser:** the launcher lists runs found under the runs
  root (newest first: timestamp, host, event count); Enter replays one in
  the observatory. `--run PATH` / `--target URL` still bypass the launcher.

## Non-goals

- Credential-test redesign (parked by the partner — later feature).
- Moving report/code-cache outputs into `~/.wpbuddy`.
- New observation modes (the "no modes" rule stands; the launcher is an
  entry screen, not a view mode).

## Testing

- Runs-root resolution unit tests (default/override/legacy-None).
- Launcher pilot tests via `run_test()`: type target, toggle options,
  launch spawns a faked scan and lands on the observatory; previous-runs
  list reads the runs root; Enter replays.
- Existing suite green; ruff clean; conftest isolates `config.RUNS_DIR`.
