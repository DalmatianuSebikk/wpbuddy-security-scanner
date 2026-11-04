# F-3 — Authenticated mode

**Goal:** let the operator hand the scanner credentials (`--cookie`,
`--app-password`) and map what those credentials unlock.

## Implemented

- `--cookie RAW`: raw `Cookie:` header attached to every request **to the
  scan target host only** — credentials must never leak to
  wpvulnerability.net / NVD / wordpress.org, which the same HTTP layer
  talks to.
- `--app-password USER:TOKEN`: WordPress application password, sent as
  `Authorization: Basic base64(user:token)`, same host restriction.
- `passive/authcheck.py`: verifies the credentials via
  `GET /wp-json/wp/v2/users/me?context=edit`, reports the account name,
  roles and the dangerous capabilities it holds (administrative surface),
  and whether `/wp-admin/` answers with the session. Runs at the end of the
  passive phase whenever credentials are configured.

## Deferred (needs engagement model + nonce machinery)

- Auth matrix probing of admin-ajax actions per capability, authenticated
  REST route enumeration diff (vs anonymous), and POST-based verification
  (nonce fetch + state-changing protections).
