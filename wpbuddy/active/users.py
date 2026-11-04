"""User enumeration - the classic WordPress weak spot.

Chain (each step only runs if the previous one came up empty):
1. /wp-json/wp/v2/users collection (passive phase already tries this)
2. per-id loop via ?rest_route=/wp/v2/users/<id> (ids start at 1, not 0)
3. ?author=<id> redirects: WordPress answers with a Location header pointing
   to /author/<slug>/ even when the REST API is fully blocked

All GET requests; responses are validated before .json() so a WAF serving
HTML with a 200 status can't crash the scanner.
"""

import re

from .. import httpclient
from ..passive import wprest

AUTHOR_SLUG_RE = re.compile(r"/author/([A-Za-z0-9_.\-]+)/?")


def enumerate_users(report, target, max_ids):
    report.section("User enumeration")
    report.paragraph("WordPress leaks usernames through several channels; exposed usernames make "
                     "credential attacks twice as cheap (no guessing needed).")

    users = wprest.users_via_rest_collection(target)
    source = "GET /wp-json/wp/v2/users"

    if users is None:
        users, source = _enumerate_via_rest_ids(target, max_ids), "REST ?rest_route= per-id probing"

    if not users:
        users, source = _enumerate_via_author_redirects(target, max_ids), "?author=<id> redirects"

    if users:
        print(f"[!] Users enumerated via {source}: {[u[1] for u in users]}")
        report.paragraph(f"Users enumerated via **{source}**:")
        report.bullets([f"**{name}** (login slug: `{slug}`)" for name, slug in users])
        report.paragraph("**Recommendation:** block user enumeration (REST filters, author archives "
                         "for logged-out visitors) - it removes half the work for attackers.")
    else:
        report.paragraph("No users could be enumerated - the site blocks REST user access and "
                         "author redirects. That's a good sign.")
    return users


def _enumerate_via_rest_ids(target, max_ids):
    users = []
    errors = 0
    for uid in range(1, max_ids + 1):
        payload = httpclient.get_json(f"{target}?rest_route=/wp/v2/users/{uid}")
        if isinstance(payload, dict) and "slug" in payload:
            users.append((payload.get("name", ""), payload["slug"]))
            errors = 0
            continue
        errors += 1
        if errors >= 3:
            print(f"[!] REST id probing aborted after {errors} consecutive dead answers "
                  f"(endpoint blocked or erroring) at id {uid}")
            break
    return users


def _enumerate_via_author_redirects(target, max_ids):
    users = []
    seen = set()
    errors = 0
    for uid in range(1, max_ids + 1):
        resp = httpclient.get(f"{target}?author={uid}")
        if resp is None or resp.status_code >= 500:
            errors += 1
            # servers that 500/fatal on author scans (e.g. security plugins) will do
            # so for EVERY id - grinding through the rest is pure noise
            if errors >= 3:
                print(f"[!] author-redirect probing aborted after {errors} consecutive "
                      f"errors at id {uid} (the site errors on author scans - see the "
                      f"error-page analysis section)")
                break
            continue
        errors = 0
        match = AUTHOR_SLUG_RE.search(resp.url)
        if match and match.group(1) not in seen:
            seen.add(match.group(1))
            users.append(("", match.group(1)))
    return users
