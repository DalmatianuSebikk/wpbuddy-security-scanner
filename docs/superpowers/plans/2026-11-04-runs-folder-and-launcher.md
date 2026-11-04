# Stable runs folder + TUI launcher Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Runs record into one stable folder (`~/.wpbuddy/previous-runs/`) instead of the process CWD, and `wpbuddy flow` with no target opens a launcher that selects scan functionality and starts the observatory.

**Architecture:** `config.RUNS_DIR` (default `~/.wpbuddy/previous-runs`) feeds `runs/store.py`'s `audit_root`; the flow command's newest-run discovery follows the same root. A Textual `LauncherScreen` (entry screen, not a view mode) builds the scan argv from 1:1 checkbox→flag mappings and reuses the existing spawn+tail path into the unchanged observatory.

**Tech Stack:** Python 3.10+, Textual (optional `[tui]` extra), stdlib.

**Spec:** `docs/superpowers/specs/2026-11-04-runs-folder-and-launcher-design.md`

## Global Constraints

- `config.RUNS_DIR is None` MUST mean the legacy CWD-relative `wpbuddy-audit/` behavior — conftest pins the whole existing suite to that, so no existing test path may change.
- Runs root layout: `<runs_root>/<host>/<run_id>/{meta.json, engagement.json, events.jsonl, artifacts/}` (host layer preserved).
- Report outputs (`outputScan*`) and the code-audit cache (`wpbuddy-audit/<host>/plugin-...`) stay CWD-relative — only the run store moves.
- Textual imports confined to `wpbuddy/tui/app.py`; launcher maps ONLY to existing CLI flags (no new scan behavior); `c` copy-command must reflect the built argv exactly.
- Credential-test checkbox exposes the CURRENT `--access` behavior only (redesign parked by the partner).
- Suite green (`pytest -q`, currently 249), `ruff check wpbuddy tests` clean, Python 3.10+.

## Review Focus

1. **`--runs-dir` on a read-only/unwritable path** — RunStore.create already degrades (store=None, scan continues); ensure no traceback reaches the operator — Task 1 test.
2. **Runs root with zero runs** — launcher list shows an empty-state line, not a crash — Task 3 test.
3. **Home-dir expansion edge** (`~` literal in `--runs-dir`) — expanduser applied — Task 1 test.
4. **Launcher toggle state vs built argv drift** (toggle → untoggle → launch) — argv must reflect final checkbox states only — Task 3 test.
5. **Legacy CWD runs still discoverable** — `flow` with no runs in the stable root falls back to scanning CWD `wpbuddy-audit/` for old runs — Task 2 test.

---

### Task 1: Stable runs root (`config.RUNS_DIR`, RunStore, `--runs-dir`)

**Files:**
- Modify: `wpbuddy/config.py`, `wpbuddy/runs/store.py`, `wpbuddy/cli.py` (`--runs-dir` flag on scan), `tests/conftest.py` (pin `RUNS_DIR = None` in the isolation fixture)
- Test: `tests/test_engine.py` (run-store tests) and `tests/test_tui.py`

**Interfaces:**
- Produces: `config.RUNS_DIR = None` (default meaning legacy CWD-relative; production default resolved in `audit_root()` as `Path.home()/".wpbuddy"/"previous-runs"` when the config value is None? NO — inverse: config carries the DEFAULT `Path.home()/".wpbuddy"/"previous-runs"` at import time; conftest overrides to None for the suite). `audit_root(base=None)` returns `base or config.RUNS_DIR or Path("wpbuddy-audit")` with `expanduser` applied. CLI flag `--runs-dir DIR` sets `config.RUNS_DIR = Path(DIR).expanduser()` before the engine starts. `RunStore` unchanged otherwise.

- [ ] **Step 1: Failing tests:** (a) with `config.RUNS_DIR` set to tmp dir A, `RunStore(host).create(...)` writes under A/host/run-id (meta.json exists); (b) with `RUNS_DIR = None`, writes under CWD `wpbuddy-audit` (legacy); (c) `~` in the path expands; (d) `scan --runs-dir X` records the run under X (cli-level test with stubbed vulndb + mock); (e) unwritable runs dir → scan still completes exit 0 and no traceback in stdout (store degrades).
- [ ] **Step 2:** RED. **Step 3:** Implement config default, `audit_root` resolution, `--runs-dir` flag, conftest pin. **Step 4:** GREEN + full suite + ruff. **Step 5:** Commit `feat(runs): stable previous-runs root (~/.wpbuddy/previous-runs, --runs-dir)`.

### Task 2: Flow honors the runs root (discovery + `--run` fallback)

**Files:**
- Modify: `wpbuddy/tui/app.py` (`run_flow` source resolution: newest under runs root, then legacy CWD `wpbuddy-audit/*/runs`; spawn-side tail uses the same root)
- Test: `tests/test_tui.py`

**Interfaces:**
- Consumes: Task 1's `audit_root()`/`config.RUNS_DIR`.
- Produces: `runs_root() -> Path` helper in app.py (importable by tests); resolution order for no-args: stable root newest → legacy CWD newest → launcher (Task 3; until then, the existing "no recorded runs" message).

- [ ] **Step 1: Failing tests:** recorded run under tmp runs root is found by no-args `run_flow` with CWD elsewhere; legacy CWD fallback found when root empty; spawn-side `_spawn_and_locate` writes/waits under the runs root.
- [ ] **Step 2:** RED. **Step 3:** Implement. **Step 4:** GREEN + suite + ruff. **Step 5:** Commit `feat(flow): discover runs under the stable root with legacy fallback`.

### Task 3: Launcher screen (no-arg `wpbuddy flow`)

**Files:**
- Modify: `wpbuddy/tui/app.py` (add `LauncherScreen`; no-arg `run_flow` opens it)
- Test: `tests/test_tui.py`

**Interfaces:**
- Produces: `LauncherScreen(textual.screen.Screen)` with: target `Input`; checkboxes deep discovery/slug enum/credential test(--access)/verify PoCs/JSON graph; cycle controls code-audit mode (off/source/target/auto) and failure gate (none/critical/high/medium/any); Launch and Open-previous-run buttons; previous-runs `ListView` (newest first: time, host, events count) from the runs root with empty-state line; `c` copies the built argv; launch → existing spawn+observatory path; `--run`/`--target` still bypass the launcher entirely.

- [ ] **Step 1: Failing pilot tests:** (a) no-arg flow mounts LauncherScreen; (b) type target + toggle deep + JSON → built argv contains `--profile deep` and `--json`, untoggle deep → argv does not; (c) cycle audit mode → `--audit-code source`; (d) launch with faked Popen (writes tiny events.jsonl under a tmp runs root) transitions to the observatory (rail mounted); (e) previous-runs list shows a run created under the tmp root, Enter opens replay; (f) empty runs root renders the empty-state line.
- [ ] **Step 2:** RED. **Step 3:** Implement LauncherScreen + wiring (markup=False everywhere operator text renders). **Step 4:** GREEN + full suite + ruff. **Step 5:** Commit `feat(flow): launcher - pick target + functionalities, browse previous runs`.

### Task 4: Docs + final verification

**Files:**
- Modify: `README.md` (flow section: launcher + previous-runs location), `tui-spec.md` (status paragraph), `exploitation-roadmap.md` (progress log line)
- Test: existing suite

- [ ] **Step 1:** Docs updates (mention `~/.wpbuddy/previous-runs`, `--runs-dir`, launcher keys; note the parked credential-test revamp in the roadmap log line).
- [ ] **Step 2:** `pytest -q` green, ruff clean, `uv build --wheel` still ships tui + data without textual.
- [ ] **Step 3:** Commit `docs: launcher + stable previous-runs folder`.
