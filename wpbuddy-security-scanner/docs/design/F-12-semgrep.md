# F-12 — PHP taint analysis / optional Semgrep rules

**Goal:** richer dataflow findings than a line-regex analyzer can provide,
without making heavyweight tools a dependency.

## Implemented (optional Semgrep integration)

- `wpbuddy/semgrep/wpbuddy.yaml`: bundled Semgrep rule pack (request-input
  to dangerous sinks: unserialize/eval/include/exec/http fetch, plus the
  preg /e modifier). Rules are conservative — they mirror the analyzer's
  own rule set with Semgrep's syntax awareness.
- `--semgrep`: when the flag is passed and a `semgrep` binary is on PATH,
  the code-audit phase runs the bundled pack over each gathered source tree
  and merges the results into the component findings (ERROR→HIGH,
  WARNING→MEDIUM, INFO→LOW). No binary / no flag → nothing changes; the
  analyzer remains the always-available baseline.
- Design constraint honored: no new runtime dependency — Semgrep stays an
  optional operator-side install (`pip install semgrep`).

## Deferred (real taint analysis)

A PHP tokenizer/AST taint engine (source → sanitizer → sink tracking,
composer-aware) is a project of its own; the engagement/evidence layer
from the exploitation roadmap is its prerequisite so results stay
reviewable.
