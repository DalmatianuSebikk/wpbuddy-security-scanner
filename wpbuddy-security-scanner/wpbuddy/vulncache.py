"""Local SQLite cache for vulnerability-database lookups (F-1).

Why: the wpvulnerability.net API is a single point of failure and a shared
rate limiter, and every scan re-fetching the same slugs is pure waste.
Cached answers (with a TTL) keep repeat scans fast, `--offline` makes
evaluations reproducible (no network variance between runs), and a stale
entry beats an outage - the alternative is scanning blind.

Design note: docs/design/F-01-local-vuln-db.md. v1 caches the responses
scans actually make; importing external feeds is future work.
"""

import json
import sqlite3
import time
from pathlib import Path

from . import config

SCHEMA_VERSION = 1

# Advisories change, but not hour-by-hour; a week-old answer is fine and a
# week-old "this slug has nothing recorded" is even stabler.
DEFAULT_TTL = 7 * 24 * 3600

_SCHEMA = ("CREATE TABLE IF NOT EXISTS lookups ("
           "kind TEXT NOT NULL, slug TEXT NOT NULL, status TEXT NOT NULL,"
           "payload TEXT, fetched_at REAL NOT NULL, schema_version INTEGER NOT NULL,"
           "PRIMARY KEY (kind, slug))")


def cache_path():
    """Where the cache lives (config.VULNDB_CACHE overrides the default)."""
    override = getattr(config, "VULNDB_CACHE", None)
    if override:
        return Path(override)
    return Path.home() / ".wpbuddy" / "vulndb.sqlite3"


def _connect():
    path = cache_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    conn.execute(_SCHEMA)
    return conn


def get(kind, slug, max_age=DEFAULT_TTL):
    """(payload dict or None, status) for a cached lookup, or None.

    max_age=None accepts any age (offline mode, outage fallback).
    Entries from an older cache schema are ignored, not migrated - the
    cache is disposable by design.
    """
    try:
        with _connect() as conn:
            row = conn.execute(
                "SELECT status, payload, fetched_at, schema_version "
                "FROM lookups WHERE kind=? AND slug=?", (kind, slug)).fetchone()
    except sqlite3.Error:
        return None
    if not row:
        return None
    status, payload, fetched_at, schema_version = row
    if schema_version != SCHEMA_VERSION:
        return None
    if max_age is not None and time.time() - fetched_at > max_age:
        return None
    try:
        data = json.loads(payload) if payload is not None else None
    except ValueError:
        return None
    return data, status


def put(kind, slug, status, data):
    """Store a completed lookup. `data` is the API `data` dict (or None)."""
    payload = json.dumps(data) if data is not None else None
    try:
        with _connect() as conn:
            conn.execute(
                "INSERT INTO lookups (kind, slug, status, payload, fetched_at, schema_version)"
                " VALUES (?, ?, ?, ?, ?, ?)"
                " ON CONFLICT(kind, slug) DO UPDATE SET"
                " status=excluded.status, payload=excluded.payload,"
                " fetched_at=excluded.fetched_at, schema_version=excluded.schema_version",
                (kind, slug, status, payload, time.time(), SCHEMA_VERSION))
    except sqlite3.Error as e:
        # the cache must never break a scan
        print(f"[*] Vulnerability cache not writable ({e}); continuing without it")


def entries():
    """[(kind, slug, status, fetched_at)] - everything currently cached."""
    try:
        with _connect() as conn:
            return conn.execute(
                "SELECT kind, slug, status, fetched_at FROM lookups"
                " ORDER BY kind, slug").fetchall()
    except sqlite3.Error:
        return []


def counts():
    """{kind: {status: n}} summary for `wpbuddy db status`."""
    out = {}
    for kind, _slug, status, _ in entries():
        out.setdefault(kind, {})
        out[kind][status] = out[kind].get(status, 0) + 1
    return out
