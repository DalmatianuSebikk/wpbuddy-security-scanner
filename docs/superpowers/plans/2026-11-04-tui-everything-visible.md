# WpBuddy TUI ("everything visible") Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A single-screen, no-modes Textual TUI (`wpbuddy flow`) that shows the whole scan flow live — banner, top bar, phase rail, phase detail, findings, event log — plus a hacker-style ASCII logo shared with the CLI banner.

**Architecture:** `wpbuddy flow` spawns the real `wpbuddy scan` subprocess and tails its `events.jsonl` run log; a pure state module (`render.py`) folds events into pane models; the Textual app renders them. Recorded runs (`--run PATH` or "latest" fallback) reuse the identical screen. No second orchestration path; Textual is an optional `[tui]` extra.

**Tech Stack:** Python 3.10+, Textual (optional extra), stdlib json/subprocess/threading; pytest + Textual `run_test()` pilot inside `asyncio.run`.

**Spec:** `docs/superpowers/specs/2026-11-04-tui-everything-visible-design.md` (delta over `tui-spec.md`)

## Global Constraints

- No new hard runtime dependency: Textual only under `[project.optional-dependencies] tui`; importable code paths outside `wpbuddy/tui/app.py` never import textual.
- The existing 205-test suite stays green; `ruff check wpbuddy tests` stays clean.
- CLI flat flag surface unchanged; `flow` is a new subcommand (§2.2 dispatch).
- Banner/logo text keeps the disclaimer lines verbatim (see Task 1 for the exact lines).
- Spec copy rules: every pane shows glyph + text (no color-only status); footer always shows key hints.

## Review Focus

1. **Truncated/corrupt JSONL line** (crash mid-write): tail must skip bad lines and keep following — test in Task 2.
2. **Empty or missing event source** (`--run` with bad path, zero-event file): clean empty state, never a traceback — Task 4.
3. **Textual not installed**: one-line install hint, exit 2, never `ImportError` — Task 4.
4. **Quit during a live run**: SIGINT to the scan subprocess (partial report per the engine crash contract), no orphan process — Task 4.
5. **Phase statuses out of order / unknown phase ids** (events for phases not in the graph): rail ignores unknown ids, detail falls back to the selected phase — Task 1.

---

### Task 1: Event board — pure state from events

**Files:**
- Create: `wpbuddy/tui/render.py`
- Test: `tests/test_tui.py`

**Interfaces:**
- Consumes: `wpbuddy.engine.phases.default_graph()` (`PhaseSpec` with `.id`, `.title`, `.purpose`, `.preconditions`, `.effects`), event dicts shaped like `wpbuddy.engine.events.Event.to_dict()` (`{"seq","ts","type","phase","data"}`).
- Produces:
  - `class ScanBoard: __init__(self, graph=None)`; `apply(self, event: dict) -> None`
  - `phases(self) -> list[tuple[str, str, str]]` — (glyph, phase_id, title); glyphs `✓ ▸ · ⊘ !`
  - `detail(self, phase_id: str) -> str` — purpose + preconditions + effects text block
  - `findings(self) -> list[tuple[str, str]]` — (severity-ish label, name) from `finding` events
  - `log_tail(self, n=200) -> list[str]` — formatted `[ts] [phase] summary` lines
  - `stats(self) -> dict` — keys `status`, `requests`, `started_ts`, `finished_ts`

- [ ] **Step 1: Write failing tests** in `tests/test_tui.py`: applying a scripted event list (`run-started`, `phase-started` passive, `phase-finished` passive, `phase-skipped` deep-discovery with reason data, `http-response` ×2, `finding` with `{name, severity}`, `run-finished`) yields: glyph sequence `✓ ✓ ⊘`-with-reason for the first three phases; `stats()["requests"] == 2`; findings list contains the finding; `log_tail()` has one line per event; `detail("passive")` contains the phase purpose sentence; an event whose `phase` is not in the graph does not crash and does not add a rail row.
- [ ] **Step 2: Run `pytest tests/test_tui.py -q` — expect ImportError/failure.**
- [ ] **Step 3: Implement `ScanBoard`** in `wpbuddy/tui/render.py` (pure stdlib, no textual import).
- [ ] **Step 4: Run tests — pass. Commit** `feat(tui): pure event board for the flow screen`.

### Task 2: Event sources — recorded replay and live tail

**Files:**
- Modify: `wpbuddy/tui/tail.py` (create)
- Test: `tests/test_tui.py`

**Interfaces:**
- Produces: `replay(path) -> Iterator[dict]` (one-shot, skips malformed lines silently, counts them via a `skipped` attribute on the generator function is NOT required — expose `read_events(path) -> tuple[list[dict], int_skipped]` used by both); `follow(path, stop_event: threading.Event, poll: float = 0.2) -> Iterator[dict]` — yields parsed events as they appear, returns after yielding a `run-finished` event or when `stop_event` is set and EOF is reached.
- Consumes: Task 1's event dict shape.

- [ ] **Step 1: Failing tests:** `read_events` on a file with one corrupt middle line returns the good events and `skipped == 1`; `follow` against a tmp file written to by the test (append 2 events, sleep, append `run-finished`) yields all three then stops.
- [ ] **Step 2: Run — fail.** Implement `tail.py`. **Run — pass. Commit** `feat(tui): events.jsonl replay + live tail`.

### Task 3: Logo and banners

**Files:**
- Create: `wpbuddy/tui/art.py`
- Modify: `wpbuddy/cli.py` (replace the `BANNER` literal with `from .tui.art import CLI_BANNER as BANNER` around line 24)
- Test: `tests/test_tui.py`

**Interfaces:**
- Produces: `LOGO: str` (multi-line figlet-style "WpBuddy", every line ≤ 78 chars, ≥ 5 lines); `CLI_BANNER: str` = LOGO + the existing intro paragraph + the two disclaimer bullets, verbatim: `- this project is related to Website Security and must not be used` / `  for malicious activities.` and `- never scan a website you do not own or are not authorized to test.`

- [ ] **Step 1: Failing tests:** every `LOGO` line is ASCII-only and ≤ 78 chars; `CLI_BANNER` contains `WpBuddy` header line and both disclaimer lines; `cli.BANNER is art.CLI_BANNER`.
- [ ] **Step 2: Run — fail.** Implement `art.py` (hand-drawn figlet letterforms; verify visually with a shell `cat`). Swap in `cli.py`. **Run — pass. Commit** `feat(tui): hacker-style ASCII logo shared by CLI + TUI`.

### Task 4: The Textual app and the `flow` subcommand

**Files:**
- Create: `wpbuddy/tui/app.py` (`FlowApp`, `textual_available()`, `run_flow(...)`)
- Modify: `wpbuddy/cli.py` (add `"flow"` + aliases `"tui"`, `"explain"` to dispatch), `pyproject.toml` (`tui = ["textual>=0.60"]` extra; dev group gains `textual`)
- Test: `tests/test_tui.py`

**Interfaces:**
- Consumes: Tasks 1–3 (`ScanBoard`, `follow`/`read_events`, `LOGO`).
- Produces:
  - `textual_available() -> bool`
  - `run_flow(argv: list[str]) -> int` — resolves the event source: `--run PATH`, else if `--target` present spawn `[sys.executable, "-m", "wpbuddy.cli", "scan", ...]` and tail `<cwd>/wpbuddy-audit/<host>/runs/<newest>/events.jsonl`, else newest recorded run under `wpbuddy-audit/`; returns exit code; sends SIGINT (process group) to a live child on quit.
  - `class FlowApp(textual.app.App)` — mounts the single screen: banner, top bar (target/profile/effects/requests/status from `board.stats()`), phase rail (ListView), phase detail (Static), findings (DataTable or ListView), event log (RichLog), footer with hints `? help  q quit  ↑↓ phases  c copy CLI`; no modes.
- [ ] **Step 1: Failing tests (no textual import at module scope — construct fakes):**
  `--run` with a bad path → exit 2 with a clean message; `textual_available()` False (monkeypatch) with `--target` → exit 2 with `pip install 'wpbuddy[tui]'` hint; `--run` with a golden small events file → `FlowApp` renders: pilot (`asyncio.run`) mounts app fed by the recorded source, assert rail contains `✓ liveness`, detail shows the purpose, log non-empty; unknown-phase event ignored.
  Live-spawn test against the bundled mock (vulndb stubbed via env? No — assert only mechanics): monkeypatch `subprocess.Popen` to a fake that writes a tiny events.jsonl then exits, assert `run_flow` tails it and exits 0, and that a still-running fake child receives SIGINT when the app quits (fake records `terminate`/`send_signal`).
- [ ] **Step 2: Run — fail.** Add the textual extra + `uv pip install -e '.[tui]' --group dev`. Implement `app.py` + dispatch. **Run — pass. Commit** `feat(tui): wpbuddy flow - single-screen live observatory`.

### Task 5: Docs, statuses, final verification

**Files:**
- Modify: `tui-spec.md` (status header: first shell shipped, no-modes delta), `exploitation-roadmap.md` (progress log line), `README.md` (one paragraph: `wpbuddy flow` + install hint)
- Test: existing suite

- [ ] **Step 1:** Update the three docs; no new tests beyond what exists.
- [ ] **Step 2:** `pytest -q` green (205+ new), `ruff check wpbuddy tests` clean, `uv build --wheel` still contains data files (tui code ships, textual does not).
- [ ] **Step 3:** Commit `docs: TUI first shell shipped - single screen, no modes`.
