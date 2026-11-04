# WpBuddy TUI — "everything visible" shell (delta design)

Date: 2026-11-04
Status: approved scope + one partner change: **no modes — one screen**

## Intent

The exploitation roadmap's final slice: a terminal UI over the scan engine.
The full vision lives in `tui-spec.md` (flow observatory, Textual, read-only
posture, later slices for lineage/ledger/breakpoints). This design covers
the first buildable slice, changed per the partner's call: the UI has **no
modes** — one screen where every pane is visible at once.

## Goals

- `wpbuddy flow --target URL` runs a scan and shows the whole flow live:
  banner + top bar (target, profile, effects, elapsed, request budget,
  status), phase rail, phase detail (purpose / preconditions / checks /
  outputs / effects from `PhaseSpec`), findings table, event log, footer
  with key hints.
- `wpbuddy flow --run <dir-or-events.jsonl>` renders a recorded run on the
  same screen (an input argument, not a mode — identical layout).
- `wpbuddy flow` with neither opens the most recent recorded run, or a
  help splash when none exist.
- Hacker-style figlet ASCII logo (`wpbuddy/tui/art.py` single source),
  shown at the splash and replacing the block-W in the CLI `BANNER`
  (intro + disclaimer text preserved).

## Non-goals (later slices per tui-spec.md delivery order)

- Explain pauses / stepping / breakpoints (needs controller gates).
- Lineage tree, confidence ledger, evidence panes, exploit/cleanup screens.
- Mouse-only affordances, animation loops, auto-rearranging panels.
- A second orchestration path (spec: forbidden).

## Approaches (picked in conversation)

1. **Textual as an optional extra `[tui]`** (picked) — consistent with the
   project's optional-dependency pattern (curl_cffi, semgrep); `wpbuddy flow`
   without Textual prints the one-line install hint and exits 2.
2. **Observe = subprocess + `events.jsonl` tail** (picked) — `flow` spawns
   the real `wpbuddy scan` subprocess and tails its run store; no in-process
   engine thread, no second orchestration path, and the footer's "copy CLI
   command" is literally the command running. Quit during a live run sends
   SIGINT so the engine's crash contract writes the partial report.
   Alternative rejected: in-process engine thread (needs pause/kill plumbing
   and risks a second orchestration path).
3. **No modes** (partner's change over the spec's four modes) — one unified
   screen; a recorded run and a live run differ only in the event source.

## Architecture

```
wpbuddy/tui/
  art.py        LOGO + BANNER_TEXT (single source, used by CLI too)
  render.py     pure state: Event -> pane updates (no Textual imports; testable)
  tail.py       follow events.jsonl (live) or iterate it (recorded)
  app.py        the Textual App: layout, panes, footer, SIGINT handling
```

- `cli.py` routes the `flow` subcommand; `BANNER` becomes
  `from .tui.art import CLI_BANNER`.
- Textual is imported only inside `app.py` (import-time guard for the
  optional extra). `pyproject` gains `tui = ["textual>=0.60"]` and the dev
  group gains textual for tests.

## Testing

- `render.py` unit tests: events mutate phase/findings/log state correctly
  (pure, fast).
- `tail.py`: live tail of a growing file; recorded iteration.
- Pilot smoke test via Textual's `run_test()` inside `asyncio.run` (no
  pytest-asyncio dependency): app mounts, a scripted event stream updates
  the rail/detail/log panes.
- CLI: `flow` without textual prints the hint (import blocked), with
  textual routed; banner contains the logo and the disclaimer.
- Existing suite must stay green; ruff clean.

## What's left to the builder

Pane wording, key bindings (spec's interaction model), spacing/colors
within Textual defaults, and the exact logo letterforms (partner previews
in the conversation message).
