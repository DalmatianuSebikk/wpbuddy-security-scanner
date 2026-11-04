# F-5 — Version detection from static assets

**Goal:** a version for components whose readme.txt is unreadable (blocked
by WAF, removed, soft-404'd) without any extra requests.

## Implemented

- `passive/assets.py` parses `wp-content/(plugins|themes)/<slug>/…?ver=X`
  from the HTML the crawl already collected. The value comes from the
  component's own code at enqueue time, so it is a first-class version
  source — placed between `style-css` (20) and `changelog-anchor` (8) at
  confidence weight 12.
- Same-site filtering mirrors the reference discovery rules (third-party
  assets cannot pin versions onto this target's components); disagreements
  between a component's assets resolve to the majority value (a stale
  cached page cannot outvote several current assets).
- Used for plugins and themes alike, only when the readme path found
  nothing.

## Deferred

Hashed-asset matching (recognizing a plugin by the filename hash of its
known assets) — needs an asset hash database to compare against.
