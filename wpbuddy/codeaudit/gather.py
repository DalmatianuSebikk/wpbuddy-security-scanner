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
import re
import zipfile
from pathlib import Path
from shutil import rmtree
from urllib.parse import unquote, urljoin, urlsplit
from xml.sax.saxutils import unescape

from bs4 import BeautifulSoup

from .. import config, httpclient
from ..versioning import compare_versions

DOWNLOAD_EXTENSIONS = {".php", ".inc", ".js", ".txt", ".md", ".html", ".css", ".json"}
MAX_DEPTH = 3

# wordpress.org info APIs: authoritative per-version download links
API_INFO = {
    "plugin": "https://api.wordpress.org/plugins/info/1.2/",
    "theme": "https://api.wordpress.org/themes/info/1.2/",
}


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


def gather_from_wordpress(kind, slug, version, dest, source_dir=None, operator_only=False):
    """Get the EXACT version's source for a component, trying several ways.

    Resolution order:
    1. operator-provided archive in source_dir ({kind}-{slug}-{version}.zip
       or {slug}-{version}.zip) - the only legitimate source for commercial
       plugins and custom code
    2. the wordpress.org info API's per-version download links (kills
       URL-naming edge cases and says definitively when a component is not
       hosted there at all)
    3. the classic direct-URL guess as a fallback

    operator_only=True stops after step 1 (used by target-mode audits:
    an operator archive never touches the target, wordpress.org is off
    limits there by contract - P1-6).

    Every successful extraction is version-VERIFIED (the archive's own
    Version:/Stable tag header must match); a mismatch is audited anyway but
    loudly labelled. Returns (dest or None, origin or None, reason or None).
    """
    if not version:
        return None, None, "no-version"

    if source_dir:
        archive = _operator_zip(source_dir, kind, slug, version)
        if archive is not None:
            return _use_archive(archive, dest, kind, slug, version,
                                f"operator-provided archive ({archive.name})")
    if operator_only:
        return None, None, "no-operator-archive"

    link, note = _api_download_link(kind, slug, version)
    if link is not None:
        resp = httpclient.get(link)
        if resp is not None and resp.status_code == 200:
            origin = f"official wordpress.org distribution, version {version}"
            if note:
                origin += f" ({note})"
            return _use_archive(io.BytesIO(resp.content), dest, kind, slug, version, origin)
        return None, None, "download-failed"   # the authoritative link didn't serve

    if note == "not-hosted":
        return None, None, "not-hosted"        # definitive - don't guess URLs

    # API unreachable, or the exact version not yet listed (the API lags the
    # CDN on brand-new releases): try the classic direct-URL guess.
    url = f"https://downloads.wordpress.org/{kind}/{slug}.{version}.zip"
    resp = httpclient.get(url)
    if resp is not None and resp.status_code == 200:
        return _use_archive(io.BytesIO(resp.content), dest, kind, slug, version,
                            f"official wordpress.org distribution, version {version}")
    return None, None, "version-not-published" if note == "version-not-published" \
        else "download-failed"


def _operator_zip(source_dir, kind, slug, version):
    """Exact operator-provided archive for this component version, or None.

    Near-misses (right slug, wrong version) are called out on the console so
    stale drops in the directory don't look like scanner failures.
    """
    directory = Path(source_dir)
    for name in (f"{kind}-{slug}-{version}.zip", f"{slug}-{version}.zip"):
        if (directory / name).is_file():
            return directory / name
    for candidate in directory.glob(f"*{slug}*.zip"):
        print(f"[!] --source-dir has {candidate.name} but the scan needs "
              f"{kind} {slug} version {version} - not using it")
    return None


def _api_download_link(kind, slug, version):
    """(download_url or None, note) from the wordpress.org info API.

    note: '' (exact hit), 'matched published X.Y.Z' (zero-padding match),
    'not-hosted', or 'version-not-published' (older releases get pruned).
    """
    payload = httpclient.get_json(API_INFO[kind], retries=1, params={
        "action": f"{kind}_information", "request[slug]": slug})
    if payload is None:
        return None, "api-unreachable"   # network/JSON failure: fall back to URL guess
    if not isinstance(payload, dict) or payload.get("error"):
        return None, "not-hosted"
    versions = payload.get("versions") or {}
    if version in versions:
        return versions[version], ""
    wanted = _normalized(version)
    for published, link in versions.items():
        if _normalized(published) == wanted:
            return link, f"matched published {published}"
    return None, "version-not-published"


def _normalized(version):
    parts = [p for p in str(version).lstrip("vV").split(".") if p]
    while len(parts) < 3:
        parts.append("0")
    return ".".join(parts)


def _use_archive(archive, dest, kind, slug, version, origin):
    """Extract, verify the archive's self-reported version, label mismatches."""
    try:
        safe_extract_zip(archive, dest)
    except (zipfile.BadZipFile, OSError) as e:
        print(f"[!] Bad archive for {slug} {version}: {e}")
        # no half-extracted tree may survive (P1-11): a partial destination
        # would later look like a complete cached source
        rmtree(dest, ignore_errors=True)
        return None, None, "bad-archive"
    found = _extracted_version(dest, kind, slug)
    if found and compare_versions(found, version) != 0:
        origin += f" - WARNING: archive self-reports {found}, expected {version}"
        print(f"[!] {slug}: archive self-reports version {found}, "
              f"expected {version} - audit results are suspect")
    return dest, origin, None


def _extracted_version(dest, kind, slug):
    """The version the extracted archive declares about itself, or None."""
    dest = Path(dest)
    primary = f"{slug}.php" if kind == "plugin" else "style.css"
    for pattern in (primary, "readme.txt"):
        for path in sorted(dest.rglob(pattern)):
            try:
                head = path.read_text(encoding="utf-8", errors="replace")[:8192]
            except OSError:
                continue
            match = re.search(r"(?mi)^\s*(?:\*\s*)?(?:Version|Stable tag):"
                              r"\s*([0-9][\w.\-]*)", head)
            if match:
                return match.group(1)
    return None


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
