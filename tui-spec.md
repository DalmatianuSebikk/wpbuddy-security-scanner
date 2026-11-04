# WpBuddy TUI — flow observatory specification

Status: **engine scaffolding done.** `wpbuddy/engine/phases.py` (graph),
`wpbuddy/engine/events.py` (typed events), `wpbuddy/engine/run.py` (engine,
`--explain`) and `wpbuddy/runs/store.py` (append-only `events.jsonl`) exist and
back the CLI. The Textual app (`wpbuddy/tui/`) is next.

Goal: a TUI that makes the **flow** of a scan understandable. It is a pipeline observatory,
not a miniature web dashboard. Every phase exposes its inputs, checks, outputs, skip reasons
and evidence; every finding exposes provenance and confidence arithmetic. Read-only observe
is the default posture; exploitation is secondary.

Command: `wpbuddy flow` (aliases `tui`, `explain`). The plain CLI stays canonical and
scriptable. Every UI action shows its equivalent CLI command.

---

## Four modes

| Mode | Purpose | Network |
|---|---|---|
| **Observe** | watch a live run, no interruptions | yes |
| **Explain** | stop at every phase boundary and rule decision; Enter continues | yes |
| **Replay** | scrub a recorded run like a debugger; every pane reflects that moment | no |
| **Demo** | scripted run against the bundled mock site with annotations | local only |

Explain is the teaching mode. Replay is how the flow is demonstrated in a thesis without a
live target.

---

## Layout

Minimum 120×35; below 100×30 the panes stack. The top bar is always visible: target,
profile, effects, elapsed, request budget, auth level, run status.

```
╭ WpBuddy Flow ─ acme.test ─ [SAFE] ─ running ─ 04:12 ─ 1,284/2,000 req ──────╮
│ PHASES                    │ PHASE 5/14: plugin versions  ▸ running         │
│                           │ purpose: read component version files          │
│ ✓ 1  Liveness             │ why now: 12 components from refs+fingerprints  │
│ ✓ 2  Core version         │ preconditions:  ✓ target alive  ✓ 12 inputs    │
│ ✓ 3  Crawl                │ inputs (12)  contact-form-7, woocommerce, …    │
│ ✓ 4  References           │ CHECKS                                         │
│ ▸ 5  Versions             │  ✓ cf7     readme.txt 200 → stable tag 5.3.1   │
│ · 6  Vuln match           │  ✗ wpdiscuz readme.txt 403 → skip (WAF)        │
│ · 7  Audit                │  ✓ woo     readme.txt 200 → stable tag 9.4.2   │
│ · 8  Access               │ outputs  2 versions, 1 skip reason             │
│ · 9  Error pages          │ effects  none                                  │
│ · 10 Report               │ [s] step  [r] rerun phase  [w] why  [l] lineage│
├───────────────────────────┴────────────────────────────────────────────────┤
│ 12:04:01 [crawl] sitemap → 5 same-host URLs                                  │
│ 12:04:03 [waf]   plain readme 403 → variant semicolon-segment 200 (bypass)   │
│ 12:04:04 [conf]  cf7 presence fingerprint 45 + stable-tag 25 = 70 LIKELY     │
├─────────────────────────────────────────────────────────────────────────────┤
│ ␣ pause  s step  t explain:ON  ⏎ inspect  g f findings  ? help  : palette    │
╰─────────────────────────────────────────────────────────────────────────────╯
```

Left rail = phase navigator. Center = selected phase. Bottom = structured event log. Right
drawer (toggle `i`) = inspector for the selected check, request or finding.

---

## Screen: Flow graph

`g g` opens the DAG in a monospaced canvas with typed edges and data badges. Phases group
into columns: **Discover → Inventory → Match → Audit → Act → Report**.

```
┌──────────┐   URLs   ┌──────────┐  slugs   ┌────────────┐  version  ┌───────────┐
│  Crawl   │─────────▶│  Refs    │─────────▶│  Versions  │──────────▶│ Vuln match│
└──────────┘          └────┬─────┘          └────────────┘           └─────┬─────┘
                           │ fingerprints                                  │ findings
                           ▼                                               ▼
                      ┌──────────┐                                   ┌───────────┐
                      │ Fingerp. │                                   │  Report   │
                      └──────────┘                                   └───────────┘
```

- Node status: `✓` done, `▸` running, `·` pending, `⊘` skipped, `!` failed, `⏸` blocked on a
  breakpoint.
- Skipped/failed nodes carry the reason as a subtitle: `⊘ enum-plugins — flag off`,
  `! audit — no source`.
- `Enter` drills into phase detail; `w` opens the “why” panel; `l` opens lineage.
- Edge badges show data type and count (`slugs ×12`), so the flow is legible without code.

Layout is static and column-based; the terminal must not rearrange itself.

---

## Screen: Phase detail

Fixed section order:

1. **Purpose** — one sentence from the phase registry docstring.
2. **Why it ran / skipped** — evaluated preconditions and the flags that produced them.
3. **Inputs** — typed list with counts and source phase.
4. **Checks / rules** — `result | rule id | short reason | code anchor`. Every skip has a
   reason; no silent skips.
5. **Outputs** — what the next phase receives.
6. **Effects and reversibility.**
7. **Requests** — count, budget, block/bypass events.

`r` re-runs only this phase with its captured inputs, `b` sets a breakpoint, `c` copies the
equivalent CLI invocation.

---

## Screen: Lineage

Collapsible provenance tree; the most important view for understanding *why* a finding
exists.

```
page /about/                         [crawled]
└─ href /wp-content/plugins/contact-form-7/…
   └─ component contact-form-7        [page-reference 25]
      ├─ fingerprint wpcf7 marker     [fingerprint 45]
      ├─ version 5.3.1                [readme 200, stable-tag 25]
      │  └─ advisory CVE-2020-35489   [bounded, title range matches]
      └─ finding HIGH                 [82 CONFIRMED]
```

Each node shows its weight and source. Selecting an advisory shows the matched range;
selecting the version opens the readme line that supplied it. Dangling references, stale
versions and contradictions are visibly marked (`⚠ 6.4.3 vs 6.6.8`).

---

## Screen: Why / confidence ledger

```
CONFIDENCE 82 — CONFIRMED
  presence      fingerprint            45   rest namespace wc/
  presence      page-reference         25   /wp-content/plugins/…
  version       stable-tag             25   readme.txt:4
  applicability bounded               +12   title “<= 5.3.2”
  corroboration 1 extra source        +12
  cap                                98
exclusions checked: prepare() absent, esc_html absent
rule fired: sqli-request at vulnplugin.php:8
```

Every weight links to evidence. In Explain mode the ledger updates as evidence arrives, so
the model is taught, not guessed.

---

## Screen: Evidence

Side-by-side request/response, baseline available for diff (`d`). Copy as curl or raw HTTP
(`y`), open in Burp (`Y`), filter cookies (`x`). Matcher results and rule anchors are pinned
above. Raw bodies are never hidden behind a collapsed row.

For skipped probes, show the block/challenge page and every bypass variant that failed.

---

## Screen: Findings

DataTable sorted by risk: severity + glyph, confidence, component/version, title, exposure,
status. `Enter` opens the finding, `w` the ledger, `l` the lineage, `p` the exploit plan when
a template exists. Bulk keys: `m` triage, `f` false-positive, `u` suppress with reason,
`n` note.

---

## Screen: Replay / scrub

Load `wpbuddy-audit/<host>/runs/<id>/events.jsonl`. A timeline bar marks phases, requests,
findings and errors. `←/→` step events, `Shift+←/→` jump phases, `Home/End` start/end. All
panes re-render to that point. Network-free.

---

## Screen: Help / glossary

`?` opens phase docs, rule docs, a flag → phase mapping and a 60-second guided tour. If a
phase or rule has no help entry, the TUI shows `undocumented` so gaps are visible.

---

## Explain annotations

```
[run]   crawl          --stealth=false, max-pages=5, sitemap found → 5 URLs
[skip]  enum-plugins   flag --enum-plugins not set
[guard] readme/wpdiscuz response is junk (soft-404 baseline match)
[rule]  file-inclusion fired vulnplugin.php:6; exclusion plugin_dir_path absent
[waf]   readme 403 → semicolon-segment 200; bypass recorded
[conf]  presence 45 + version 25 + bounded 12 = 82 CONFIRMED
```

Every annotation names the mechanism (`flag`, `guard`, `rule`, `exclusion`, `waf`, `conf`) so
a reader can map it to code. Explain pauses before the next phase and shows the pending
decision: `Enter continue / s skip / i inspect`.

---

## Interaction model

- `?` help, `:` command palette, `/` search, `Tab` cycle panes, `Esc` close drawer, `q` quit
  (confirms while running).
- `Space` pause after current request; `Shift+Space` kill and keep the partial report.
- `b` breakpoint on phase/rule/finding; `B` list breakpoints.
- `c` copy equivalent CLI command; `x` export current view to Markdown.
- Vim movement in tables/trees; no action without a visible footer key hint.

---

## Architecture

- `wpbuddy/engine/phases.py` — `PhaseSpec`, `SubphaseSpec`, `PhaseGraph`; single source of
  truth for order, preconditions, docs and effects. CLI and TUI read the same graph.
- `wpbuddy/engine/events.py` — typed events; `EventBus`.
- `wpbuddy/engine/run.py` — orchestrator; emits events, no Rich/Textual imports.
- `wpbuddy/runs/store.py` — append-only `events.jsonl` + `meta.json`; `replay.py`.
- `wpbuddy/tui/app.py` — Textual `App`, screens, widgets.
- `wpbuddy/tui/controller.py` — engine worker; pause/step/breakpoint gates.
- `wpbuddy/tui/demo.py` — scripted fixtures for the tour.

Textual widgets: `PhaseRail(ListView)`, `FlowCanvas`, `PhasePanel(TabbedContent)`,
`Inspector`, `LineageTree(Tree)`, `ConfidenceLedger`, `EvidencePanes`, `EventLog(RichLog)`,
`FindingsTable(DataTable)`, `CommandPalette`, `HelpScreen(ModalScreen)`, `ConfirmScreen`.

---

## Safety and failure states

- Profile and effect chips pinned in the header; destructive actions open a `ConfirmScreen`
  with the cleanup plan and require the target hostname.
- WAF challenge, DB offline, partial scan, cleanup pending, budget exhausted: persistent
  banners.
- A crashed phase renders `!` with the exception, traceback file and preserved partial
  report; the run does not vanish.
- No auto-scroll hijack: new log lines pulse a counter unless the log pane is focused.
- Screen-reader fallback: `--no-color --json-stream` plus `x` export.

---

## Delivery order

1. **[done]** Phase registry, event bus, JSONL run store, CLI `--plan` / `--explain` / `--no-run-log`.
2. Textual shell: header, phase rail, phase detail, event log.
3. Lineage + confidence ledger + evidence panes.
4. Explain/step/breakpoint controller.
5. Replay scrubber and demo script.
6. Findings/status actions, then exploit-plan and cleanup screens.
7. Pilot tests, golden JSONL, screenshots, docs.

Tests: `App.run_test()` for navigation and breakpoints; golden event files for replay; CI
check that every phase has help text and a test.

---

## What not to do

- No animation loops, spinners everywhere or auto-rearranging panels.
- No decision hidden behind a log line — every skip is a row with a reason.
- No mouse-only affordances.
- No color-only status; always glyph + text.
- No exploit confirmation buried in a submenu.
- No second orchestration path for the TUI.
