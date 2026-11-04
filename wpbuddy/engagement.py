"""Engagement model (roadmap section 2.3): scope, authorization, budgets.

An Engagement is the operator's contract with the scanner: what may be
touched, what effects are allowed, and when to stop. It precedes any
aggressive feature - the discovery worker (stage 1) and the exploit runner
(stage 2) both consume the SAME engagement rather than each growing its
own flags.

Persisted as engagement.json inside the run directory (wpbuddy/runs), so
every recorded run carries its own scope - the audit trail roadmap
section 2 asks for.

Effects vocabulary (roadmap section 5): read-only work is 'read';
state-changing work declares what it changes. The default engagement
allows exactly 'read' - a tool that changes state by default is unusable
on production without a briefing.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

# The closed vocabulary of side effects an action can declare (roadmap §5).
EFFECTS = ("read", "file-write", "code-exec", "user-create", "credential", "session")


@dataclass
class Engagement:
    """The operator's contract: scope, authorization, budgets, effects."""

    target: str
    host: str = ""
    authorization: str = ""          # free text / reference proving consent
    excluded_paths: tuple[str, ...] = ()   # path prefixes never requested
    max_requests: int | None = None  # hard ceiling for this run (None = no cap)
    max_seconds: float | None = None  # wall-clock ceiling
    allowed_effects: tuple[str, ...] = ("read",)
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc)
                            .isoformat(timespec="seconds"))

    # ---------------------------------------------------------------- persistence
    def to_dict(self):
        return {
            "target": self.target, "host": self.host,
            "authorization": self.authorization,
            "excluded_paths": list(self.excluded_paths),
            "max_requests": self.max_requests, "max_seconds": self.max_seconds,
            "allowed_effects": list(self.allowed_effects),
            "created_at": self.created_at,
        }

    @classmethod
    def from_dict(cls, raw):
        return cls(target=raw["target"], host=raw.get("host", ""),
                   authorization=raw.get("authorization", ""),
                   excluded_paths=tuple(raw.get("excluded_paths", ())),
                   max_requests=raw.get("max_requests"),
                   max_seconds=raw.get("max_seconds"),
                   allowed_effects=tuple(raw.get("allowed_effects", ("read",))),
                   created_at=raw.get("created_at", ""))

    def save(self, path):
        Path(path).write_text(json.dumps(self.to_dict(), indent=2), encoding="utf-8")

    @classmethod
    def load(cls, path):
        return cls.from_dict(json.loads(Path(path).read_text(encoding="utf-8")))

    # ---------------------------------------------------------------- gates
    def allows_effect(self, *effects):
        """True when every declared effect is inside the engagement's scope."""
        return all(effect in self.allowed_effects for effect in effects)

    def excludes(self, url):
        """True when a URL's path starts with an excluded prefix."""
        from urllib.parse import urlsplit
        path = (urlsplit(url).path or "/").lower().rstrip("/") + "/"
        for prefix in self.excluded_paths:
            prefix = "/" + prefix.strip().lower().strip("/")
            if prefix != "/" and path.startswith(prefix):
                return True
        return False


@dataclass
class Budget:
    """Enforces an engagement's request/time ceilings.

    record_request() is called by the HTTP layer before sending: it returns
    False (and remembers why) when the engagement is exhausted - the caller
    must not send. Exclusions are answered by the engagement before any
    budget is spent.
    """

    max_requests: int | None = None
    max_seconds: float | None = None
    requests: int = 0
    started_at: float = field(default_factory=time.monotonic)
    _reason: str | None = None

    @classmethod
    def from_engagement(cls, engagement):
        return cls(max_requests=engagement.max_requests,
                   max_seconds=engagement.max_seconds)

    def record_request(self):
        """Count one outgoing request; False when the budget is spent."""
        if self.max_requests is not None and self.requests >= self.max_requests:
            self._reason = f"request budget exhausted ({self.max_requests} requests)"
            return False
        if self.max_seconds is not None and time.monotonic() - self.started_at > self.max_seconds:
            self._reason = f"time budget exhausted ({self.max_seconds:.0f}s)"
            return False
        self.requests += 1
        return True

    @property
    def exceeded_reason(self):
        return self._reason

    def to_dict(self):
        return {"requests": self.requests,
                "max_requests": self.max_requests,
                "max_seconds": self.max_seconds,
                "elapsed": round(time.monotonic() - self.started_at, 1),
                "exceeded": self._reason}
