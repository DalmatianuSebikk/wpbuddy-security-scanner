"""Evidence and artifact store for one run (roadmap section 2.5).

The run log (runs/store.py) already records every HTTP request/response
and typed events with timestamps. This module adds the missing half of
the evidence layer: ARTIFACTS - files an action produced or captured
(exploit output, raw request bytes, dump snippets) - plus a cleanup log
so stage 4 can replay reversals.

Everything lands inside the run directory
(`wpbuddy-audit/<host>/runs/<run_id>/artifacts/`), so a run stays a
single self-describing unit: meta.json (what/when), engagement.json
(scope), events.jsonl (timeline), artifacts/ (evidence files).
"""

from __future__ import annotations

import json
from pathlib import Path


class EvidenceStore:
    """Artifacts + cleanup records for one run directory."""

    def __init__(self, run_dir, emit=None):
        self.run_dir = Path(run_dir)
        self.artifacts_dir = self.run_dir / "artifacts"
        self.registry_path = self.run_dir / "artifacts.json"
        self._emit = emit          # callable(type, **data) -> Event or None
        self._registry = None

    # ---------------------------------------------------------------- registry
    def _load(self):
        if self._registry is None:
            try:
                self._registry = json.loads(self.registry_path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                self._registry = {"artifacts": [], "cleanup": []}
        return self._registry

    def _flush(self):
        self.registry_path.parent.mkdir(parents=True, exist_ok=True)
        self.registry_path.write_text(json.dumps(self._load(), indent=2), encoding="utf-8")

    # ---------------------------------------------------------------- artifacts
    def save_artifact(self, name, content, description=""):
        """Write inline evidence (bytes/str) under artifacts/ and register it."""
        safe = Path(name).name          # no path games inside the run dir
        self.artifacts_dir.mkdir(parents=True, exist_ok=True)
        path = self.artifacts_dir / safe
        if isinstance(content, str):
            path.write_text(content, encoding="utf-8")
        else:
            path.write_bytes(content)
        return self.register_artifact(path, description)

    def register_artifact(self, path, description=""):
        """Record an existing file (e.g. the report) as a run artifact."""
        registry = self._load()
        entry = {"path": str(path), "description": description,
                 "name": Path(path).name}
        registry["artifacts"].append(entry)
        self._flush()
        if self._emit is not None:
            self._emit("artifact", name=entry["name"], path=entry["path"],
                       description=description)
        return entry

    def artifacts(self):
        return list(self._load()["artifacts"])

    # ---------------------------------------------------------------- cleanup
    def record_cleanup(self, artifact_name, status, detail=""):
        """Append to the cleanup log (stage 4 replays it in reverse)."""
        registry = self._load()
        registry["cleanup"].append({"artifact": artifact_name, "status": status,
                                    "detail": detail})
        self._flush()
        if self._emit is not None:
            self._emit("cleanup", artifact=artifact_name, status=status, detail=detail)

    def cleanup_log(self):
        return list(self._load()["cleanup"])
