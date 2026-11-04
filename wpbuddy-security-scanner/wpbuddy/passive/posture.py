"""DNS / email / TLS posture checks (F-8).

The certificate and the domain's email-spoofing posture are attack surface
around the WordPress install itself - cheap to check, high signal for the
site owner. TLS costs one handshake (https targets only); SPF/DMARC/CAA
are TXT-family lookups done best-effort with the system resolver tools
(the stdlib has no TXT API and the project takes no new runtime deps).

No tool available -> that part of the section is skipped, never guessed.
"""

import re
import shutil
import socket
import ssl
import subprocess
from datetime import datetime, timezone
from urllib.parse import urlsplit

DNS_TOOL_TIMEOUT = 5

_WEAK_SPF_RE = re.compile(r"\+all|^\s*v=spf1\s*(?:[^\s;]*\s)*$")


def _txt_records(name, rtype="TXT"):
    """TXT/CAA records via dig or nslookup, or None when neither exists.

    Returns [] when the tool answered with no records (a definitive
    'nothing published') and None when we could not ask at all.
    """
    commands = {
        "TXT": (["dig", "+short", "-t", "TXT", name], ["nslookup", "-type=TXT", name]),
        "CAA": (["dig", "+short", "-t", "CAA", name], ["nslookup", "-type=CAA", name]),
    }
    for cmd in commands.get(rtype, ()):
        if not shutil.which(cmd[0]):
            continue
        try:
            out = subprocess.run(cmd, capture_output=True, text=True,
                                 timeout=DNS_TOOL_TIMEOUT).stdout
        except (OSError, subprocess.TimeoutExpired):
            continue
        return [ln.strip().strip('"') for ln in out.splitlines() if ln.strip()]
    return None


def _parse_spf(txt_records):
    """(spf record or None, weak: bool). Weak = permissive or unterminated."""
    spf = next((r for r in txt_records or [] if r.lower().startswith("v=spf1")), None)
    if spf is None:
        return None, False
    weak = bool(re.search(r"\+all", spf)) or not re.search(r"[-+~?]all$", spf.strip())
    return spf, weak


def _parse_dmarc(txt_records):
    """DMARC policy (none/quarantine/reject) or None when unpublished."""
    record = next((r for r in txt_records or [] if "v=dmarc1" in r.lower()), None)
    if record is None:
        return None
    match = re.search(r"\bp\s*=\s*(\w+)", record, re.I)
    return match.group(1).lower() if match else None


def _days_left(not_after):
    """Days until a cert's notAfter ('May 12 12:00:00 2026 GMT'), or None."""
    try:
        expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
    except (TypeError, ValueError):
        return None
    return (expiry.replace(tzinfo=timezone.utc) - datetime.now(timezone.utc)).days


def _tls_facts(host, timeout=5.0):
    """Protocol/expiry facts from one TLS handshake, or None when it fails."""
    try:
        context = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as tls:
                protocol = tls.version()
                cert = tls.getpeercert() or {}
    except (OSError, ValueError):
        return None
    return {
        "protocol": protocol,
        "days_left": _days_left(cert.get("notAfter")),
        "issuer": ", ".join(v for part in cert.get("issuer", ()) for v in part[::2]),
    }


def check(report, target):
    """Render the TLS + email posture section for a target."""
    from .content import _base_domain
    report.section("TLS / DNS / email posture")
    parts = urlsplit(target)
    host = (parts.hostname or "").lower()
    domain = _base_domain(host)

    if parts.scheme == "https":
        facts = _tls_facts(host)
        if facts is None:
            report.paragraph(f"Could not establish TLS to `{host}:443` - certificate "
                             f"and protocol could not be checked.")
        else:
            report.paragraph(f"TLS: **{facts['protocol']}** served by "
                             f"{facts['issuer'] or 'an unnamed issuer'}.")
            days = facts["days_left"]
            if days is not None:
                if days < 0:
                    print(f"[!] TLS certificate for {host} EXPIRED {-days} days ago")
                    report.paragraph(f"**Certificate EXPIRED {-days} days ago** - browsers "
                                     f"block the site and interim proxies may accept "
                                     f"re-issued hostile certificates. Renew now.")
                elif days < 30:
                    print(f"[!] TLS certificate for {host} expires in {days} days")
                    report.paragraph(f"**Certificate expires in {days} days** - schedule "
                                     f"the renewal before it becomes an outage.")
                else:
                    report.paragraph(f"Certificate valid for another {days} days.")
            weak = {"TLSv1": True, "TLSv1.0": True, "TLSv1.1": True,
                    "SSLv3": True, "SSLv2": True}.get(str(facts["protocol"]), False)
            if weak:
                report.paragraph(f"**Weak protocol {facts['protocol']} accepted** - "
                                 f"disable it server-side (TLS 1.2 minimum).")
    else:
        report.paragraph("Target scanned over plain HTTP - no TLS handshake to inspect "
                         "(see the HTTP security headers section for the HTTPS advice).")

    if domain:
        spf_txt = _txt_records(domain)
        if spf_txt is None:
            report.paragraph("Email posture skipped - no `dig`/`nslookup` available to "
                             "read TXT records.")
            return
        spf, weak_spf = _parse_spf(spf_txt)
        if spf is None:
            report.paragraph(f"**No SPF record on {domain}** - anyone can send email "
                             f"claiming to be this domain (phishing aid). Publish "
                             f"`v=spf1 ... -all`.")
        elif weak_spf:
            report.paragraph(f"**Weak SPF** on {domain} (`{spf}`) - the record is "
                             f"permissive or unterminated; end it with `-all`.")
        else:
            report.paragraph(f"SPF published on {domain} (`{spf}`).")

        dmarc_policy = _parse_dmarc(_txt_records(f"_dmarc.{domain}"))
        if dmarc_policy is None:
            report.paragraph(f"**No DMARC record on _dmarc.{domain}** - receivers have "
                             f"no policy for spoofed mail from this domain.")
        elif dmarc_policy == "none":
            report.paragraph(f"**DMARC policy is `p=none`** on {domain} - monitoring "
                             f"only, no enforcement; move to quarantine/reject when "
                             f"alignment is understood.")
        else:
            report.paragraph(f"DMARC policy `{dmarc_policy}` on {domain}.")

        caa = _txt_records(domain, rtype="CAA")
        if caa:
            report.paragraph("CAA records pin which CAs may issue for the domain: "
                             + ", ".join(f"`{c}`" for c in caa[:5]) + ".")
