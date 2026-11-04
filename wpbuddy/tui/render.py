"""Pure event-board state: fold recorded scan events into pane models.

`ScanBoard` is the TUI's memory, deliberately boring: `apply()` consumes
event dicts shaped like `Event.to_dict()` (`wpbuddy.engine.events`) and the
accessors return plain strings/tuples/dicts that a pane renders verbatim.
The same board serves a live tail and a recorded replay, and because it is
pure stdlib it can be unit-tested without a terminal.

Every phase state is rendered as a glyph plus text (never color-only):
`✓` finished, `▸` running, `·` pending, `⊘` skipped, `!` failed.
"""

from __future__ import annotations

from ..engine.phases import default_graph

# One glyph per phase state; the rail and the detail header both use it.
GLYPHS = {
    "pending": "·",
    "running": "▸",
    "finished": "✓",
    "skipped": "⊘",
    "failed": "!",
}

# phase events -> the state they put a phase in.
_PHASE_STATES = {
    "phase-started": "running",
    "phase-finished": "finished",
    "phase-skipped": "skipped",
    "phase-failed": "failed",
}

# Data keys tried, in order, when an event type has no dedicated summary.
_GENERIC_KEYS = ("message", "summary", "detail", "name", "component", "purpose")


class ScanBoard:
    """Folds an event stream into the flow screen's pane models."""

    def __init__(self, graph=None):
        if graph is None:
            graph = default_graph()
        self._specs = {spec.id: spec for spec in graph}
        self._state = {phase_id: "pending" for phase_id in self._specs}
        self._skip_reasons: dict[str, list[str]] = {}
        self._fail_messages: dict[str, str] = {}
        self._requests = 0
        self._status = "pending"
        self._started_ts: str | None = None
        self._finished_ts: str | None = None
        self._findings: list[tuple[str, str]] = []
        self._log: list[str] = []

    # -------------------------------------------------------------- input

    def apply(self, event: dict) -> None:
        """Fold one event dict into the board. Never raises on odd shapes."""
        event_type = event.get("type") or ""
        phase = event.get("phase")
        data = event.get("data") or {}
        ts = event.get("ts") or ""
        if event_type == "run-started":
            self._started_ts = ts
            self._status = "running"
        elif event_type == "run-finished":
            self._finished_ts = ts
            self._status = str(data.get("status") or "finished")
        elif event_type in _PHASE_STATES:
            self._apply_phase_event(event_type, phase, data)
        elif event_type == "http-response":
            self._requests += 1
        elif event_type == "finding":
            label = str(data.get("severity") or "unrated").upper()
            name = str(data.get("name") or data.get("detail") or "finding")
            self._findings.append((label, name))
        self._log.append(_format_line(ts, phase, event_type, data))

    def _apply_phase_event(self, event_type, phase, data):
        """Phase events only move phases the graph knows; others are ignored."""
        if phase not in self._specs:
            return
        state = _PHASE_STATES[event_type]
        self._state[phase] = state
        if state == "skipped":
            self._skip_reasons[phase] = [str(r) for r in (data.get("reasons") or [])]
        elif state == "failed":
            self._fail_messages[phase] = str(data.get("message") or "failed")

    # ------------------------------------------------------------ outputs

    def phases(self) -> list[tuple[str, str, str]]:
        """(glyph, phase_id, title) for every graph phase, in graph order."""
        return [(GLYPHS[self._state[spec.id]], spec.id, spec.title)
                for spec in self._specs.values()]

    def detail(self, phase_id: str) -> str:
        """Purpose + preconditions + effects block, plus skip/fail reasons."""
        spec = self._specs.get(phase_id)
        if spec is None:
            return ""
        state = self._state[phase_id]
        preconditions = "; ".join(pre.description for pre in spec.preconditions)
        lines = [
            f"{GLYPHS[state]} {spec.title}",
            "",
            f"purpose: {spec.purpose}",
            f"preconditions: {preconditions or 'none'}",
            f"effects: {', '.join(spec.effects) or 'none'}",
        ]
        if state == "skipped":
            reasons = "; ".join(self._skip_reasons.get(phase_id) or ()) or "skipped"
            lines.append(f"skipped: {reasons}")
        elif state == "failed":
            lines.append(f"failed: {self._fail_messages.get(phase_id, 'failed')}")
        return "\n".join(lines)

    def findings(self) -> list[tuple[str, str]]:
        """(severity-ish label, name) for every `finding` event so far."""
        return list(self._findings)

    def log_tail(self, n=200) -> list[str]:
        """The last n formatted `[ts] [phase] summary` lines."""
        if n <= 0:
            return []
        return list(self._log[-n:])

    def stats(self) -> dict:
        """Top-bar numbers: status, completed requests, run time window."""
        return {
            "status": self._status,
            "requests": self._requests,
            "started_ts": self._started_ts,
            "finished_ts": self._finished_ts,
        }


# ------------------------------------------------------------- formatting

def _format_line(ts, phase, event_type, data):
    """One log-pane line: `[ts] [phase] summary`."""
    return f"[{ts or '-'}] [{phase or '-'}] {_summary(event_type, data)}".rstrip()


def _summary(event_type, data):
    """A one-line, human-readable summary for any event type."""
    if event_type == "run-started":
        return f"scan started: {data['target']}" if data.get("target") else "scan started"
    if event_type == "run-finished":
        return f"run finished: {data.get('status') or 'done'}"
    if event_type == "phase-started":
        return str(data.get("purpose") or "started")
    if event_type == "phase-finished":
        return "finished"
    if event_type == "phase-skipped":
        return "; ".join(str(r) for r in (data.get("reasons") or [])) or "skipped"
    if event_type == "phase-failed":
        return str(data.get("message") or "failed")
    if event_type == "check-started":
        return f"check {data.get('subphase') or '?'} started"
    if event_type == "check-finished":
        return f"check {data.get('subphase') or '?'} done"
    if event_type == "http-request":
        return f"{data.get('method') or 'GET'} {data.get('url') or ''}".strip()
    if event_type == "http-response":
        if data.get("error"):
            return f"{data.get('url') or 'request'} failed: {data['error']}"
        status = data.get("status")
        return f"{data.get('url') or 'request'} -> {status if status is not None else '?'}"
    if event_type == "finding":
        return f"{data.get('name') or data.get('detail') or 'finding'}" \
               f" ({data.get('severity') or 'unrated'})"
    if event_type == "artifact":
        return str(data.get("path") or data.get("name") or "artifact")
    if event_type == "cleanup":
        return str(data.get("summary") or data.get("detail") or "cleanup")
    if event_type == "waf-detected":
        return f"{data.get('name') or 'WAF'} via {data.get('via') or '?'}"
    if event_type == "waf-block":
        return "probe blocked"
    if event_type == "waf-bypass":
        return str(data.get("detail") or data.get("technique") or "bypass")
    if event_type == "error-page":
        return f"HTTP {data.get('status')} {data.get('url') or ''}".strip()
    if event_type == "confidence":
        return f"{data.get('component')} score={data.get('score')}" \
               f" {data.get('tier') or ''}".strip()
    for key in _GENERIC_KEYS:
        if data.get(key):
            return str(data[key])
    return str(event_type)
