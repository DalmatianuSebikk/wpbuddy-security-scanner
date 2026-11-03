# F-6 — Bundled-dependency SCA

**Goal:** plugins ship whole vendor trees; a perfectly patched plugin can
bundle a library with a famous RCE. The audit already has the source - now
it reads its manifests.

## Implemented

- `codeaudit/deps.py` parses `composer.lock` (packages + packages-dev) and
  `package.json` (pinned dependencies only - ranges are listed as inventory,
  not matched) from the gathered source tree of every audited component.
- A small curated advisory table maps package → first fixed version
  (PHPMailer ≥ 5.2.27 / CVE-2016-10045, guzzle ≥ 6.2.1 / CVE-2016-5385
  httpoxy, psr7 1.x < 1.9.1 / CVE-2022-24775). Installed versions below a
  fixed release are reported as HIGH findings with the update target; the
  whole table is plain data at the top of the module so extending it is a
  one-line change.
- Every component report gets a bundled-package inventory (the supply-chain
  surface) plus any advisories.

## Deferred

A real OSV-style feed (offline DB once F-1's cache machinery grows a
general store) and transitive dependency resolution for `package.json`
ranges.
