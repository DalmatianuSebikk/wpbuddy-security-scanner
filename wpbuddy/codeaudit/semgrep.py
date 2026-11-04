"""Optional Semgrep integration for the code audit (F-12).

Semgrep gives syntax-aware dataflow rules the line-regex analyzer cannot;
it stays an OPTIONAL operator-side install (no new runtime dependency):
without a `semgrep` binary on PATH this module reports unavailability and
the analyzer remains the baseline.
"""

import json
import shutil
import subprocess
from pathlib import Path

RULES_PATH = Path(__file__).resolve().parent.parent / "semgrep" / "wpbuddy.yaml"
SEMGREP_TIMEOUT = 180

# semgrep severity -> wpbuddy severity
_SEVERITY_MAP = {"error": "HIGH", "warning": "MEDIUM", "info": "LOW",
                 "ERROR": "HIGH", "WARNING": "MEDIUM", "INFO": "LOW"}


def available():
    return shutil.which("semgrep") is not None


def scan(source_dir):
    """Analyzer-shaped findings from the bundled rule pack, or None
    (not available / failed / no matches)."""
    if not available():
        print("[*] --semgrep ignored: no semgrep binary on PATH (pip install semgrep)")
        return None
    try:
        result = subprocess.run(
            ["semgrep", "scan", "--json", "--config", str(RULES_PATH),
             "--no-git-ignore", "--quiet", str(source_dir)],
            capture_output=True, text=True, timeout=SEMGREP_TIMEOUT,
        )
    except (OSError, subprocess.TimeoutExpired) as e:
        print(f"[*] semgrep run failed ({e}); continuing with the built-in analyzer")
        return None
    try:
        payload = json.loads(result.stdout)
    except ValueError:
        print("[*] semgrep produced no JSON; continuing with the built-in analyzer")
        return None
    findings = []
    for item in payload.get("results", []):
        extra = item.get("extra", {})
        findings.append({
            "severity": _SEVERITY_MAP.get(extra.get("severity"), "MEDIUM"),
            "rule": item.get("check_id", "semgrep-finding"),
            "description": extra.get("message", "semgrep match"),
            "file": str(Path(item.get("path", "")).relative_to(source_dir))
                    if str(item.get("path", "")).startswith(str(source_dir))
                    else item.get("path", ""),
            "line": (item.get("start") or {}).get("line", 0),
            "snippet": (extra.get("lines") or "").strip()[:160],
            "params": [],
        })
    if findings:
        print(f"[*] semgrep: {len(findings)} additional dataflow finding(s)")
    return findings
