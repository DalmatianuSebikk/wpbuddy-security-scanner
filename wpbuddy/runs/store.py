"""Append-only run log: `<runs-root>/<host>/runs/<run_id>/`.

The runs root is the stable `~/.wpbuddy/previous-runs` (config.RUNS_DIR);
an explicit base (or --runs-dir) wins, and RUNS_DIR = None restores the
legacy CWD-relative `wpbuddy-audit/`.

Each run gets `meta.json` (what/when/argv) and `events.jsonl` (one event per
line, monotonic `seq`). The log is written by a bus subscriber and is never
rewritten, so a crashed run stays inspectable and replayable. Replay is a
pure file iterator: no network, no scanner imports.
"""

from __future__ import annotations

import json
import os
import secrets
from datetime import datetime
from pathlib import Path

from .. import __version__, config
from ..engine.events import Event


def audit_root(base=None):
    """Explicit base wins, then config.RUNS_DIR (`~` expanded; None = the
    legacy CWD-relative wpbuddy-audit/)."""
    if base:
        return Path(base).expanduser()
    runs_dir = getattr(config, "RUNS_DIR", None)
    if runs_dir is not None:
        return Path(runs_dir).expanduser()
    return Path("wpbuddy-audit")


class RunStore:
    """Creates run directories and appends events."""

    def __init__(self, host, base=None):
        self.host = host or "target"
        self.base = audit_root(base)
        self.run_id = None
        self.dir = None
        self.attached = False
        self.error = None

    def create(self, target, argv=(), started=None):
        """Create the run directory and meta.json. Returns run_id or None."""
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        self.run_id = f"{stamp}-{secrets.token_hex(3)}"
        self.dir = self.base / self.host / "runs" / self.run_id
        try:
            self.dir.mkdir(parents=True, exist_ok=True)
            self.write_meta({
                "run_id": self.run_id,
                "wpbuddy_version": __version__,
                "target": target,
                "host": self.host,
                "argv": list(argv),
                "started_at": (started or datetime.now()).isoformat(timespec="seconds"),
                "status": "running",
            })
        except OSError as exc:
            self.error = exc
            self.dir = None
            return None
        return self.run_id

    def write_meta(self, meta):
        if self.dir is None:
            return
        path = self.dir / "meta.json"
        tmp = path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(meta, indent=2, default=str), encoding="utf-8")
        os.replace(tmp, path)

    def finish(self, meta):
        current = {}
        try:
            current = json.loads((self.dir / "meta.json").read_text(encoding="utf-8"))
        except (OSError, ValueError):
            pass
        current.update(meta)
        current["finished_at"] = datetime.now().isoformat(timespec="seconds")
        try:
            self.write_meta(current)
        except OSError:
            pass

    def append(self, event):
        if self.dir is None:
            return
        try:
            with open(self.dir / "events.jsonl", "a", encoding="utf-8") as fh:
                fh.write(event.to_json() + "\n")
        except OSError as exc:
            # One bad write must not spam a line into every later event.
            if self.error is None:
                self.error = exc

    def attach(self, bus):
        """Subscribe the append-only writer; returns the unsubscribe callable."""
        self.attached = True
        return bus.subscribe(self.append)

    def events(self):
        """Yield recorded events for this run (empty when unreadable)."""
        if self.dir is None:
            return
        path = self.dir / "events.jsonl"
        try:
            with open(path, encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        yield Event.from_dict(json.loads(line))
                    except (ValueError, KeyError):
                        continue
        except OSError:
            return


def run_dir(host, run_id, base=None):
    return audit_root(base) / (host or "target") / "runs" / run_id


def iter_events(host, run_id, base=None):
    """Replay iterator for a recorded run, ordered by the log as written."""
    store = RunStore(host, base)
    store.dir = run_dir(host, run_id, base)
    yield from store.events()


def list_runs(host, base=None):
    """Recorded run ids for a host, newest first."""
    runs = audit_root(base) / (host or "target") / "runs"
    try:
        return sorted((p.name for p in runs.iterdir() if p.is_dir()), reverse=True)
    except OSError:
        return []
