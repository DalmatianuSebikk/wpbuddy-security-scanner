"""Event sources for the flow screen: recorded replay and live tail.

Two iterators feed `ScanBoard` (`wpbuddy.tui.render`) the same event dicts a
run's `events.jsonl` holds, one JSON object per line (see `wpbuddy.runs.store`):
`replay` reads a finished run in one shot, `follow` tails a file another
process is appending to, stopping after a `run-finished` event or when the
caller sets `stop_event`. Malformed lines never raise: `read_events` counts
them, the iterators skip them silently. Pure stdlib, no Textual.
"""

from __future__ import annotations

import json
import threading
from collections.abc import Iterator


def _parse(line: str) -> dict | None:
    """The event dict on one `events.jsonl` line, None when it isn't one."""
    try:
        event = json.loads(line)
    except ValueError:
        return None
    return event if isinstance(event, dict) else None


def read_events(path) -> tuple[list[dict], int]:
    """Parse a finished run's events.jsonl: (events, malformed lines skipped).

    Every line that does not hold a JSON object counts as skipped, so
    `skipped == total lines - len(events)`.
    """
    events: list[dict] = []
    skipped = 0
    try:
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                event = _parse(line)
                if event is None:
                    skipped += 1
                else:
                    events.append(event)
    except OSError:
        return [], 0
    return events, skipped


def replay(path) -> Iterator[dict]:
    """Yield every recorded event of a finished run, malformed lines skipped."""
    events, _ = read_events(path)
    yield from events


def follow(path, stop_event: threading.Event, poll: float = 0.2) -> Iterator[dict]:
    """Yield events while another process appends them to `path`.

    Waits for the file to exist, then polls for new complete lines. Returns
    after yielding a `run-finished` event, or once `stop_event` is set and
    the file is at EOF. A line the writer has not finished yet is left for
    the next poll, never half-parsed.
    """
    fh = None
    partial = ""
    try:
        while True:
            if fh is None:
                try:
                    fh = open(path, encoding="utf-8")
                except OSError:
                    if stop_event.wait(poll):  # stop asked before the file exists
                        return
                    continue
            chunk = fh.read()
            if not chunk:
                if stop_event.wait(poll):  # EOF: honour a pending stop request
                    return
                continue
            lines = (partial + chunk).split("\n")
            partial = lines.pop()  # tail after the last newline: wait for it
            for line in lines:
                event = _parse(line)
                if event is None:
                    continue
                yield event
                if event.get("type") == "run-finished":
                    return
    finally:
        if fh is not None:
            fh.close()
