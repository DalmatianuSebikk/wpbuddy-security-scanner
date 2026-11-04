"""Typed scan events and an in-process event bus.

The engine, the HTTP layer, the collectors and the confidence model emit
here; the CLI's `--explain` printer, the append-only run log and (later) the
TUI subscribe. Events are deliberately boring data (a type, the phase they
belong to, a JSON-serializable payload) so a recorded run can be replayed
without importing any scanning code.

A broken subscriber must never break a scan: `EventBus.emit` isolates
subscriber exceptions and records them for the caller.
"""

from __future__ import annotations

import json
import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

# Response bodies are truncated in the event log; the report and audit tree
# remain the authoritative evidence, the log only has to be legible.
BODY_PREVIEW = 1200


class EventType(str, Enum):
    """Every event the engine can emit.

    Values are the wire format used by `events.jsonl` and the TUI, so they
    are stable kebab-case strings rather than Python names.
    """

    RUN_STARTED = "run-started"
    RUN_FINISHED = "run-finished"
    PHASE_STARTED = "phase-started"
    PHASE_FINISHED = "phase-finished"
    PHASE_SKIPPED = "phase-skipped"
    PHASE_FAILED = "phase-failed"
    CHECK_STARTED = "check-started"
    CHECK_FINISHED = "check-finished"
    HTTP_REQUEST = "http-request"
    HTTP_RESPONSE = "http-response"
    WAF_DETECTED = "waf-detected"
    WAF_BLOCK = "waf-block"
    WAF_BYPASS = "waf-bypass"
    ERROR_PAGE = "error-page"
    CONFIDENCE = "confidence"
    FINDING = "finding"
    ARTIFACT = "artifact"
    CLEANUP = "cleanup"
    LOG = "log"
    ERROR = "error"

    def __str__(self):  # pragma: no cover - convenience only
        return self.value


@dataclass(frozen=True)
class Event:
    """One recorded fact about a run."""

    type: str
    phase: str | None = None
    data: dict[str, Any] = field(default_factory=dict)
    ts: str = field(default_factory=lambda: datetime.now(timezone.utc)
                    .isoformat(timespec="milliseconds"))
    seq: int = 0

    def __post_init__(self):
        if isinstance(self.type, EventType):
            object.__setattr__(self, "type", self.type.value)

    def to_dict(self):
        return {"seq": self.seq, "ts": self.ts, "type": self.type,
                "phase": self.phase, "data": self.data}

    @classmethod
    def from_dict(cls, raw):
        return cls(type=raw["type"], phase=raw.get("phase"),
                   data=raw.get("data") or {}, ts=raw.get("ts") or "",
                   seq=int(raw.get("seq") or 0))

    def to_json(self):
        return json.dumps(self.to_dict(), ensure_ascii=False, default=str)


class EventBus:
    """Synchronous fan-out with subscriber isolation and a bounded history."""

    def __init__(self, history_limit=5000):
        self._subscribers: list[Callable[[Event], None]] = []
        self._history: list[Event] = []
        self._history_limit = history_limit
        self._seq = 0
        self._lock = threading.Lock()
        self.errors: list[str] = []

    def subscribe(self, callback):
        """Register a subscriber; returns the unsubscribe callable."""
        self._subscribers.append(callback)

        def unsubscribe():
            try:
                self._subscribers.remove(callback)
            except ValueError:
                pass

        return unsubscribe

    def emit(self, event):
        """Publish an event. Subscriber failures are isolated, never raised."""
        with self._lock:
            self._seq += 1
            object.__setattr__(event, "seq", self._seq)
            self._history.append(event)
            if len(self._history) > self._history_limit:
                del self._history[:len(self._history) - self._history_limit]
            subscribers = tuple(self._subscribers)
        for callback in subscribers:
            try:
                callback(event)
            except Exception as exc:  # a view must not kill the scan
                self.errors.append(f"{type(exc).__name__}: {exc}")
        return event

    def emitter(self, phase=None):
        """A `(type, **data)` callable bound to one phase (handed to phases)."""
        def emit(event_type, **data):
            return self.emit(Event(event_type, phase=phase, data=data))
        return emit

    def history(self):
        with self._lock:
            return list(self._history)


# --------------------------------------------------------------------------
# Process-wide sink for modules that cannot be handed a bus (httpclient,
# waf, errorpages, confidence). The engine sets it for the duration of a run
# and always clears it in `finalize`; without a sink every emit is a no-op.
# --------------------------------------------------------------------------

_sink: EventBus | None = None


def set_sink(bus):
    global _sink
    _sink = bus


def clear_sink():
    global _sink
    _sink = None


def sink():
    return _sink


def emit_event(event_type, phase=None, **data):
    """Emit into the active sink, if any. Never raises."""
    bus = _sink
    if bus is None:
        return None
    try:
        return bus.emit(Event(event_type, phase=phase, data=data))
    except Exception:  # pragma: no cover - defensive
        return None


def emit_http_request(method, url):
    return emit_event(EventType.HTTP_REQUEST, method=method, url=url)


def emit_http_response(resp, elapsed_ms, error=None):
    """Record a response (or the final transport failure) compactly."""
    if resp is None:
        return emit_event(EventType.HTTP_RESPONSE, url=None, status=None,
                          elapsed_ms=round(elapsed_ms, 1), error=str(error)[:300] if error else None)
    try:
        body = (getattr(resp, "text", "") or "")[:BODY_PREVIEW]
        headers = {str(k).lower(): str(v)[:200]
                   for k, v in (getattr(resp, "headers", None) or {}).items()}
        length = len(getattr(resp, "content", b"") or b"")
    except Exception:  # logging must never break the request path
        body, headers, length = "", {}, None
    return emit_event(EventType.HTTP_RESPONSE, url=getattr(resp, "url", None),
                      status=getattr(resp, "status_code", None),
                      content_type=headers.get("content-type"),
                      length=length,
                      elapsed_ms=round(elapsed_ms, 1), body=body,
                      blocked=getattr(resp, "status_code", None) in (403, 406, 501))
