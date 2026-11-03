# F-9 — More active checks

**Goal:** the cheap, high-signal WordPress-specific checks the scanner was
missing.

## Implemented

**Passive (GET-only, `passive/extrachecks.py`)**

- `wp-cron.php` reachable — every bot can trigger the scheduler
  (load-amplification surface; hardening advice: `DISABLE_WP_CRON` +
  system cron).
- `wp-admin/install.php` / `wp-admin/upgrade.php` reachable and serving
  their forms — installation-remainder findings, same family as the
  setup-config check.
- REST CORS reflection — `GET /wp-json/` with an attacker `Origin`:
  reflected origin **with** `Access-Control-Allow-Credentials: true` is a
  HIGH finding (credentialed cross-origin reads); reflection without
  credentials is WP's documented default and reported as informational.
- Login cookie flags — `Set-Cookie` on `wp-login.php` without `HttpOnly`
  (and without `Secure` on https targets).
- Three more `wp-config` backup variants in the sensitive-file list
  (`.txt`, `.copy`, `wp-config.old`).

**Active (`active/extrachecks.py`, runs with the active phase)**

- Unauthenticated `admin-ajax.php` heartbeat probe — answers mean the
  AJAX router is open to anonymous traffic (recon + load surface).
- `pingback.ping` in the XML-RPC method list is called out explicitly
  (SSRF/tracking surface) instead of hiding in the method count.

## Deferred

pingback SSRF callback verification (needs a listener the operator
controls) and a full public admin-ajax action wordlist.
