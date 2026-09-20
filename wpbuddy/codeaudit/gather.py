"""Source-code acquisition for the local audit phase.

Two ways to get the code of a discovered component, tried in order:

1. from the TARGET itself - when directory listing is enabled under
   wp-content/<kind>/<slug>/ we can mirror the actually-deployed files
   (this is also a vulnerability finding on its own)
2. from wordpress.org - the exact version detected on the target can be
   downloaded from the official distribution (downloads.wordpress.org),
   which touches the target ZERO more times (fully stealthy)

The downloaded code is then inspected locally by wpbuddy.codeaudit.analyzer.
"""

import io
import posixpath
import zipfile
from pathlib import Path
from urllib.parse import unquote, urljoin, urlsplit
from xml.sax.saxutils import unescape

from bs4 import BeautifulSoup

from .. import config, httpclient

DOWNLOAD_EXTENSIONS = {".php", ".inc", ".js", ".txt", ".md", ".html", ".css", ".json"}
MAX_DEPTH = 3


def gather_from_target(listing_url, dest, max_files=config.MAX_AUDIT_FILES):
    """Mirror an Apache-style directory listing into dest. Returns dest or None."""
    resp = httpclient.get(listing_url)
    if resp is None or resp.status_code != 200 or "Index of /" not in resp.text:
        return None

    queue = [(listing_url.rstrip("/") + "/", 0)]
    count = 0
    while queue and count < max_files:
        dir_url, depth = queue.pop(0)
        resp = httpclient.get(dir_url)
        if resp is None or resp.status_code != 200 or "Index of /" not in resp.text:
            continue
        for entry_url, is_dir in _listing_entries(resp.text, dir_url):
            if is_dir:
                if depth < MAX_DEPTH:
                    queue.append((entry_url, depth + 1))
                continue
            local = _local_path(dest, dir_url, entry_url)
            if local is None or local.exists():
                continue
            if local.suffix.lower() not in DOWNLOAD_EXTENSIONS:
                continue
            file_resp = httpclient.get(entry_url)
            if file_resp is None or file_resp.status_code != 200:
                continue
            if len(file_resp.content) > config.MAX_AUDIT_FILE_SIZE:
                continue
            local.parent.mkdir(parents=True, exist_ok=True)
            local.write_bytes(file_resp.content)
            count += 1
            if count >= max_files:
                print(f"[*] Audit file cap ({max_files}) reached for {listing_url}")
                break
    return dest if count else None


def _listing_entries(html, dir_url):
    """Parse an Apache-style listing into [(absolute_url, is_dir)]."""
    soup = BeautifulSoup(html, "html.parser")
    entries = []
    for a in soup.find_all("a", href=True):
        href = unescape(a["href"])
        if href.startswith(("#", "?", "//", "javascript:")) or href in (".", "..", "../", "/"):
            continue
        if a.get_text(strip=True).lower().startswith("parent dir"):
            continue
        absolute = urljoin(dir_url, href)
        # Only direct children of the listed directory; keeps ../, siblings
        # and absolute third-party links out.
        if not absolute.startswith(dir_url) or absolute == dir_url:
            continue
        entries.append((absolute, absolute.endswith("/")))
    return entries


def gather_from_wordpress(kind, slug, version, dest):
    """Download the exact plugin/theme version from the official wordpress.org
    distribution. `kind` is 'plugin' or 'theme'. Returns dest or None."""
    if not version:
        return None
    url = f"https://downloads.wordpress.org/{kind}/{slug}.{version}.zip"
    resp = httpclient.get(url)
    if resp is None or resp.status_code != 200:
        print(f"[!] Could not download {slug} {version} from wordpress.org")
        return None
    try:
        safe_extract_zip(io.BytesIO(resp.content), dest)
    except (zipfile.BadZipFile, OSError) as e:
        print(f"[!] Bad zip for {slug} {version}: {e}")
        return None
    return dest


def safe_extract_zip(zfile_like, dest):
    """Extract a zip while refusing path traversal (zip-slip) entries."""
    dest = Path(dest).resolve()
    with zipfile.ZipFile(zfile_like) as zf:
        for info in zf.infolist():
            name = posixpath.normpath(info.filename)
            if name.startswith(("/", "..")) or ".." in Path(name).parts:
                raise zipfile.BadZipFile(f"unsafe path in archive: {info.filename}")
            target = (dest / name).resolve()
            if not str(target).startswith(str(dest)):
                raise zipfile.BadZipFile(f"path escapes destination: {info.filename}")
            if info.is_dir():
                target.mkdir(parents=True, exist_ok=True)
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(zf.read(info))


def _local_path(dest, dir_url, file_url):
    """Map a fetched file URL to a local path mirroring the URL structure."""
    tail = file_url[len(dir_url):]
    if not tail or "/" in tail.rstrip("/"):  # only direct children land here
        return None
    dir_path = urlsplit(dir_url).path.strip("/")
    return Path(dest) / Path(*dir_path.split("/")) / unquote(tail)
