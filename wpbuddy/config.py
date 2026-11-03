"""Shared configuration: paths and defaults."""

from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

# The data files ship INSIDE the package in an installed wheel (pyproject's
# force-include maps data/ to wpbuddy/data); a repository checkout keeps
# them at the project root. Prefer the packaged copy, fall back to the repo
# layout - both dev runs and installed-wheel runs must find them (P1-10).
_PKG_DATA_DIR = Path(__file__).resolve().parent / "data"
DATA_DIR = _PKG_DATA_DIR if _PKG_DATA_DIR.is_dir() else BASE_DIR / "data"

# HTTP defaults (see wpbuddy.httpclient)
DEFAULT_TIMEOUT = 10.0
DEFAULT_RETRIES = 3
RETRY_DELAY = 3.0

# Politeness delay in seconds applied after every request when > 0.
# Set from the CLI (--delay); 0 means "as fast as possible".
REQUEST_DELAY = 0.0

# Covert-traffic settings (see wpbuddy.stealth / --covert)
REQUEST_JITTER = 0.0      # extra uniform random pause in [0, jitter] per request
PERSONA = None            # browser persona for the whole scan (set by init_networking)
HTTP_BACKEND = "requests"  # or "curl_cffi" when impersonation is active
EVADE = True              # retry WAF-blocked probes through path obfuscation (--no-evade)

# Hostname of the scan target (set by the CLI). Passive collectors (WAF
# fingerprinting, error pages) only trust responses from THIS host - a
# firewall on wpvulnerability.net or NVD must never be reported as the
# target's.
TARGET_HOST = None

# Vulnerability-database cache (F-1): path override for tests / sandboxes,
# and the offline switch (--offline serves cached answers only).
VULNDB_CACHE = None
OFFLINE = False

# Authenticated mode (F-3): operator-supplied credentials, attached to
# requests ONLY for the scan target host (never to the data APIs).
AUTH_COOKIE = None     # raw Cookie header value (--cookie)
AUTH_BASIC = None      # pre-encoded Basic credentials (--app-password)

# Passive crawling
MAX_CRAWL_PAGES = 5

# User enumeration
MAX_USER_IDS = 25

# Code audit
MAX_AUDIT_FILES = 60
MAX_AUDIT_FILE_SIZE = 1_000_000  # skip files bigger than 1 MB (likely minified/assets)
MAX_POC_VERIFICATIONS = 15       # live PoC attempts per scan (--verify-pocs)
MAX_POC_TIME_BUDGET = 90.0       # wall-clock seconds for live PoC attempts (F-11)
MAX_REPORT_FINDINGS = 40         # per component; extras are summarized, not listed
MAX_POC_TEMPLATES = 20           # manual-PoC commands listed per component

# Plugin slug enumeration (--enum-plugins)
DEFAULT_ENUM_LIMIT = 300


def load_lines(path):
    """Read a text file of one-entry-per-line, skipping blanks and comments."""
    try:
        return [line.strip() for line in Path(path).read_text(encoding="utf-8").splitlines()
                if line.strip() and not line.strip().startswith("#")]
    except OSError as e:
        print(f"[!] Could not read {path}: {e}")
        return []
