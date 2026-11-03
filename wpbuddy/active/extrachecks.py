"""Extra active checks (F-9): one-POST probes that need a body."""

from .. import httpclient


def check_admin_ajax_anonymous(report, target):
    """admin-ajax.php answering anonymous traffic at all.

    The heartbeat is WordPress-core and answers logged-out visitors with a
    nonce - its openness is documented, but it proves the AJAX router is
    reachable and will execute registered `wp_ajax_nopriv_*` handlers.
    """
    resp = httpclient.post(f"{target}admin-ajax.php",
                           data={"action": "heartbeat",
                                 "data[server_time]": "1"},
                           retries=1)
    if resp is None or resp.status_code != 200:
        return
    body = resp.text or ""
    if "wp-refresh-nonces" not in body and "server_time" not in body:
        return  # not a real heartbeat answer
    print("[*] admin-ajax.php answers unauthenticated heartbeat requests")
    report.paragraph("`admin-ajax.php` answers **unauthenticated** heartbeat POSTs - "
                     "the AJAX router is open to anonymous traffic and every "
                     "`wp_ajax_nopriv_*` handler registered by a plugin is reachable "
                     "without an account. Audit those handlers (the code audit flags "
                     "missing capability checks in them).")


def run(report, target):
    check_admin_ajax_anonymous(report, target)
