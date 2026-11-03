# F-11 — PoC verifier hardening

**Goal:** fewer false "VERIFIED" claims and bounded verification cost.

## Implemented

- **Multi-parameter payloads**: every request parameter found on the
  finding line is tried, not just the first — a vulnerable sink reached
  through the second parameter used to ship as "unverified template".
- **Per-rule confirmation signals**:
  - `xss-echo`: verified only when the literal `<script>console.log(…)`
    payload comes back **unescaped** (entity-encoded reflections no longer
    count).
  - `file-inclusion`: `/etc/passwd` first, with a `root:` content
    signature as the strongest evidence line, then the php://filter and
    hostname probes.
  - `sqli-request`: error-based signal unchanged (quote → SQL error text
    absent from baseline).
- **Budgets**: the attempt cap stays (`MAX_POC_VERIFICATIONS`) and a
  wall-clock budget (`MAX_POC_TIME_BUDGET`, 90 s default) stops
  verification early; remaining findings still get manual templates.

## Deferred

Time-based (blind) SQL confirmation — needs a safe, repeatable delay
measurement and risks load on the target.
