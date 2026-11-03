"""Authenticated surface mapping (F-3).

When the operator supplies credentials (--cookie / --app-password), the
passive phase checks who those credentials belong to and what they unlock:
the roles, the dangerous capabilities, and whether /wp-admin/ opens. An
over-privileged service account used for scanning is itself a finding.

GET-only; no state changes.
"""

from .. import config, httpclient

# capability -> what having it means for an attacker holding this account
INTERESTING_CAPS = {
    "manage_network": "full multisite control",
    "manage_options": "site settings, can usually install plugins",
    "install_plugins": "can install plugins -> arbitrary code",
    "edit_plugins": "can edit plugin PHP -> arbitrary code",
    "edit_themes": "can edit theme PHP -> arbitrary code",
    "upload_files": "can upload files into wp-content",
    "edit_users": "can create/modify accounts",
}


def check(report, target):
    """Report the identity and reach of the supplied credentials."""
    report.section("Authenticated surface (supplied credentials)")
    report.paragraph("The operator-supplied credentials were verified against "
                     "the site's own REST identity endpoint; this section maps "
                     "what an attacker holding exactly these credentials gets.")

    resp = httpclient.get(f"{target}wp-json/wp/v2/users/me?context=edit", retries=1)
    if resp is None or resp.status_code != 200:
        detail = "unreachable" if resp is None else f"HTTP {resp.status_code}"
        report.paragraph(f"The credentials could not be verified ({detail} on "
                         "`/wp-json/wp/v2/users/me`) - they are still applied to "
                         "every target request, but no identity could be read.")
        return

    try:
        me = resp.json()
    except ValueError:
        me = None
    if not isinstance(me, dict):
        report.paragraph("The identity endpoint answered but not with a user object.")
        return

    roles = me.get("roles") or []
    caps = me.get("capabilities") or {}
    held = [f"**{cap}** ({why})" for cap, why in INTERESTING_CAPS.items() if caps.get(cap)]

    print(f"[*] Supplied credentials: {me.get('name') or me.get('slug')} "
          f"({', '.join(roles) or 'no roles'})")
    report.paragraph(f"Credentials belong to **{me.get('name') or me.get('slug')}** "
                     f"(roles: {', '.join(f'`{r}`' for r in roles) or 'none listed'}).")
    if held:
        report.paragraph("Capabilities worth noting for post-exploitation reach:")
        report.bullets(held)
    else:
        report.paragraph("No high-value capabilities listed for this account "
                         "(least privilege - good).")

    # does the classic dashboard open with this session?
    admin = httpclient.get(f"{target}wp-admin/", retries=1)
    if admin is not None and admin.status_code == 200 and "wp-login.php" not in (admin.url or ""):
        report.paragraph("`/wp-admin/` answers directly with these credentials - "
                         "full dashboard access is part of the blast radius.")
    elif admin is not None:
        report.paragraph(f"`/wp-admin/` did not open with these credentials "
                         f"(final: `{admin.url}`, HTTP {admin.status_code}).")
    if not (config.AUTH_COOKIE or config.AUTH_BASIC):
        report.paragraph("(No credentials were actually configured.)")
