# F-1 — Local vulnerability DB + `--offline`

**Goal:** remove the hard runtime dependency on wpvulnerability.net and make
scan results reproducible offline.

## Scope of v1 (implemented)

- `wpbuddy/vulncache.py`: SQLite cache (default `~/.wpbuddy/vulndb.sqlite3`,
  override with `config.VULNDB_CACHE`) keyed by `(kind, slug)` storing the
  response **status** (`ok` / `not-found`) and payload, with a schema version
  and a 7-day TTL.
- `vulndb._fetch` consults the cache first; fresh hits never touch the
  network, network failures fall back to a stale entry rather than reading
  as "database unreachable", and `not-found` answers are cached too (they
  dominate lookups for non-wordpress.org slugs).
- `--offline`: lookups are served from the cache only (any age); a miss is
  reported as `unreachable` — never as "no vulnerabilities".
- `wpbuddy db status` / `wpbuddy db update`: inspect the cache / re-fetch
  every stored entry now. Implemented as a light subcommand dispatch in
  `cli.main` so the existing flat flag interface is untouched.

## Deliberately deferred

- Importing third-party feeds (WPScan / Patchstack / Wordfence) into the same
  schema — the cache already removes the single-API failure mode; feed
  licensing and normalization need their own pass.
- Prefetching whole popularity lists (`db update --all`).
