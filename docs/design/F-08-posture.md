# F-8 — DNS / email / TLS posture

**Goal:** the cheapest real attack surface checks around a WordPress site:
the certificate, and the email-spoofing posture of its domain.

## Implemented (`passive/posture.py`, run with the passive phase)

- **TLS**: one handshake to the target (only for `https://` targets):
  protocol version (TLS < 1.2 flagged), days to certificate expiry
  (< 30 warning, expired critical), issuer shown.
- **Email**: SPF and DMARC TXT records of the site's registrable domain.
  Missing SPF, permissive SPF (`+all` / no terminating mechanism), missing
  DMARC, and `p=none` DMARC each get a finding (spoofing/BJM-fraud
  enablers). CAA records listed when present.
- TXT/CAA lookups shell out to `dig`/`nslookup` best-effort (the stdlib has
  no DNS TXT API and no new runtime dependency is allowed); when no tool
  exists the email part is skipped, never faked.

## Deferred

DKIM (needs per-selector probing), full certificate-chain/protocol audit,
and verified subdomain-takeover fingerprints (needs CNAME walks + fetching
the dangling hosts - engagement territory).
