# F-4 — Core integrity + modified-file detection

**Goal:** detect that deployed code is no longer the code wordpress.org
shipped — the classic post-compromise / nulled-plugin signal.

## Implemented

- **Component integrity**: whenever the audit phase mirrors a plugin/theme
  from an exposed listing (target mode / auto), it now also fetches the
  official distribution of the *exact same version* from wordpress.org (no
  target requests) and compares the two trees:
  - *modified* — same path, different bytes
  - *added* — in the deployed code but not in the official archive
  - *removed* — filtered to text-type files only (images/assets are
    legitimately absent from a text-only mirror)
  Byte-identical mirrors get an explicit "matches the official distribution"
  confirmation — absence of tampering is a finding worth reading too.

## Blocked / deferred

- **Core integrity**: the official checksums API
  (`api.wordpress.org/core/checksums/1.0/`) is only useful with a mirror of
  the target's core files; the scanner never mirrors core (huge, noisy).
  Version-freshness findings (readme.html, meta generator, feed) remain the
  core signal. A `--mirror-core` option would unlock this.
- wordpress.org SVN comparison for plugins: same shape as the archive
  comparison; deferred until per-file SVN fetches are worth the requests.
