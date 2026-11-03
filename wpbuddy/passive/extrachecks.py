"""Extra passive checks (F-9): wp-cron, install remainder, CORS, cookies.

All GET-only. Each check is small and independently skippable - a WAF'd or
hardened site just yields no finding.
"""

import re

from .. import httpclient

INSTALL_FORM_RE = re.compile(r"name=[\"']dbname[\"']|Installation|upgrade", re.I)


def run(report, target):
    check_wp_cron(report, target)
    check_install_pages(report, target)
    check_rest_cors(report, target)
    check_cookie_flags(report, target)


def check_wp_cron(report, target):
    """wp-cron.php answers anyone: bots can hammer the scheduler."""
    resp = httpclient.get(f"{target}wp-cron.php", retries=1, allow_redirects=False)
    if resp is None or resp.status_code != 200:
        return
    print("[*] wp-cron.php is reachable by anyone")
    report.paragraph("**wp-cron.php is publicly reachable** - every visitor (and bot) can "
                     "trigger the scheduler, which turns traffic into load amplification. "
                     "Prefer `define('DISABLE_WP_CRON', true)` plus a real system cron entry.")


def check_install_pages(report, target):
    """Installation/upgrade leftovers: wp-admin/install.php / upgrade.php
    still serving their forms."""
    for path, severity in (("wp-admin/install.php", "**HIGH**"),
                           ("wp-admin/upgrade.php", "")):
        resp = httpclient.get(f"{target}{path}", retries=1, allow_redirects=False)
        if resp is None or resp.status_code != 200:
            continue
        if not INSTALL_FORM_RE.search(resp.text or ""):
            continue
        print(f"[!] Installation page still reachable: {path}")
        report.paragraph(f"{severity + ' - ' if severity else ''}`{path}` is reachable and "
                         f"serving its form - installation/upgrade remainder. These pages "
                         f"assume a trusted installer; on a live site they are attack "
                         f"surface (and a deployment hygiene signal). Remove or restrict "
                         f"them (the files are unneeded after installation).")


def check_rest_cors(report, target):
    """Does /wp-json/ reflect an arbitrary Origin - and with credentials?"""
    resp = httpclient.get(f"{target}wp-json/", retries=1,
                          headers={"Origin": "https://attacker.example"})
    if resp is None:
        return
    acao = resp.headers.get("Access-Control-Allow-Origin")
    if acao not in ("https://attacker.example", "*"):
        return
    credentials = (resp.headers.get("Access-Control-Allow-Credentials") or "").lower() == "true"
    if credentials:
        print("[!] REST CORS reflects arbitrary origins WITH credentials")
        report.paragraph("**REST API reflects arbitrary CORS origins with credentials "
                         "enabled** (`Access-Control-Allow-Origin: "
                         + acao + "`, `Allow-Credentials: true`) - any website can read "
                         "authenticated REST responses in a visitor's browser. Restrict "
                         "the allowed origins or drop credentials.")
    else:
        report.paragraph(f"REST API reflects arbitrary CORS origins (`{acao}`) without "
                         f"credentials - WordPress's documented default; only state-changing "
                         f"unauthenticated routes make this dangerous, so it is noted, not "
                         f"alarmed.")


def check_cookie_flags(report, target):
    """Login cookies without HttpOnly (and Secure on https) are theft-prone."""
    resp = httpclient.get(f"{target}wp-login.php", retries=1)
    if resp is None:
        return
    cookies = resp.headers.get("Set-Cookie", "")
    if not cookies:
        return
    problems = []
    if "httponly" not in cookies.lower():
        problems.append("no `HttpOnly` flag (script-readable cookies)")
    if "secure" not in cookies.lower() and target.startswith("https://"):
        problems.append("no `Secure` flag on an HTTPS site")
    if problems:
        print(f"[*] Login cookie flags: {', '.join(problems)}")
        report.paragraph("**Login cookie hardening** - `wp-login.php` sets cookies with "
                         + " and ".join(problems)
                         + ". Cookie flags are cheap defenses against XSS-powered session "
                           "theft; set them in `wp-config.php`/server config.")
