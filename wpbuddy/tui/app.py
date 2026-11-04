"""The Textual shell of the flow screen: `wpbuddy flow`.

This is the only module anywhere in the package that imports Textual, and
it does so behind a guard so everything else keeps working when the extra
is missing: `textual_available()` answers through `importlib.util.find_spec`
(it never imports Textual), `FlowApp` subclasses the real App when the
extra is installed and a bare placeholder otherwise, and `run_flow()` bails
with an install hint before building any UI.

`run_flow` resolves the event source, `FlowApp` renders it. One screen, no
modes: header, top bar, phase rail, phase detail, findings, event log and a
key-hint footer are always mounted; `?` overlays the about pane, `c` copies
the command that produced the run, `q` quits (interrupting a live scan with
SIGINT to its process group first).
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import shlex
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path
from urllib.parse import urlsplit

from .art import LOGO
from .render import ScanBoard
from .tail import follow, replay

try:  # the 'tui' extra; without it FlowApp stays importable but unusable
    from textual.app import App
    from textual.binding import Binding
    from textual.containers import Horizontal, Vertical
    from textual.widgets import Label, ListItem, ListView, RichLog, Static
except ImportError:  # pragma: no cover - only reachable without the extra
    App = object  # type: ignore[assignment,misc]
    Binding = tuple  # type: ignore[assignment,misc]  # inert placeholder

# Key hints for the footer; the about pane repeats them.
HINTS = "↑↓ phases  ?: about  q quit  c copy CLI"
_DESCRIPTION = ("WpBuddy Flow — the single-screen flow observatory: every phase, "
                "finding and request of a scan, live or replayed, on one screen.")
ABOUT_TEXT = f"{LOGO}\n\n{_DESCRIPTION}\n\nkeys: {HINTS}"

# A live child gets SIGINT, then this many seconds to wrap up, then SIGKILL.
_INTERRUPT_GRACE = 5.0
# How long to wait for a freshly spawned scan to create its run log.
_RUN_APPEAR_TIMEOUT = 30.0
_POLL_INTERVAL = 0.1
# How many log-pane lines to ask the board for (keeps the pane bounded).
_LOG_WINDOW = 1000


def textual_available() -> bool:
    """True when the textual extra is importable; never imports it."""
    return importlib.util.find_spec("textual") is not None


class FlowApp(App):
    """The flow observatory screen: every pane always mounted, no modes."""

    CSS = """
    #header { height: 1; color: $accent; text-style: bold; }
    #topbar { height: 1; }
    #mid { height: 1fr; }
    #rail { width: 38; border: round $panel; }
    #right { width: 1fr; }
    #detail { height: 1fr; border: round $panel; padding: 0 1; }
    #findings { height: 30%; border: round $panel; }
    #log { height: 10; border: round $panel; }
    #about { height: 1fr; border: thick $accent; padding: 0 1; }
    #footer { height: 1; color: $text-muted; }
    """
    BINDINGS = [
        Binding("q", "quit", "quit"),
        Binding("c", "copy_command", "copy CLI"),
        Binding("question_mark", "toggle_about", "about"),
    ]

    def __init__(self, source, board=None, command="", target="scan",
                 profile="safe", stop_event=None):
        super().__init__()
        self._source = source  # zero-arg callable returning an event iterator
        self.board = board if board is not None else ScanBoard()
        self.command = command  # what `c` copies: the spawn cmd / replay cmd
        self.target = target
        self.profile = profile
        self.stop_event = stop_event if stop_event is not None else threading.Event()
        self.source_done = threading.Event()  # set once the source is drained
        self.log_lines_rendered = 0  # log pane appends only lines it has not shown
        self._events_seen = 0  # one board log line exists per applied event

    # -------------------------------------------------------------- layout

    def compose(self):
        yield Static(f"{LOGO.splitlines()[0]}  WpBuddy Flow — {self.target}",
                     id="header", markup=False)
        yield Static("", id="topbar", markup=False)
        with Horizontal(id="mid"):
            yield ListView(id="rail")
            with Vertical(id="right"):
                yield Static("", id="detail", markup=False)
                yield ListView(id="findings")
        yield RichLog(id="log")
        yield Static(ABOUT_TEXT, id="about", markup=False)
        yield Static(HINTS, id="footer", markup=False)

    def on_mount(self) -> None:
        self.query_one("#about").display = False  # overlay pane, hidden until `?`
        self.query_one("#rail", ListView).border_title = "phases"
        self.query_one("#detail", Static).border_title = "phase detail"
        self.query_one("#findings", ListView).border_title = "findings"
        self.query_one("#log", RichLog).border_title = "event log"
        self.query_one("#rail", ListView).focus()  # ↑↓ drive the rail out of the box
        self.refresh_panes()
        threading.Thread(target=self._pump_source, daemon=True).start()

    # -------------------------------------------------------------- events

    def apply_event(self, event: dict) -> None:
        """Fold one event into the board and refresh the panes it touches."""
        self.board.apply(event)
        self._events_seen += 1
        self.refresh_panes()

    def _pump_source(self) -> None:
        """Worker thread: feed source events to the UI thread one by one."""
        try:
            for event in self._source():
                self.call_from_thread(self.apply_event, event)
        except Exception as exc:  # a broken source must never take the app down
            try:
                self.call_from_thread(self._report_source_error, exc)
            except RuntimeError:  # app already shut down
                pass
        finally:
            try:
                self.call_from_thread(self.source_done.set)
            except RuntimeError:  # app already shut down
                self.source_done.set()

    def _report_source_error(self, exc: Exception) -> None:
        """A frozen feed must be visible in the log pane, not silent."""
        self.query_one("#log", RichLog).write(f"[!] event source failed: {exc}")

    # ------------------------------------------------------------ refresh

    def refresh_panes(self) -> None:
        """Re-derive every pane from the board (log appends only new lines)."""
        stats = self.board.stats()
        self.query_one("#topbar").update(
            f"target {self.target} · profile {self.profile} · "
            f"requests {stats['requests']} · status {stats['status']}")
        self._rebuild_list("#rail", [f"{glyph} {phase_id} {title}"
                                     for glyph, phase_id, title in self.board.phases()])
        self._rebuild_list("#findings", [f"{label} — {name}"
                                         for label, name in self.board.findings()])
        self._refresh_detail()
        self._append_log()

    def _rebuild_list(self, selector: str, rows: list[str]) -> None:
        """Swap a ListView's items, keeping the operator's selection."""
        view = self.query_one(selector, ListView)
        selected = view.index
        view.clear()
        view.extend([ListItem(Label(row, markup=False)) for row in rows])
        if selector == "#rail" and len(rows) and (selected is None or selected >= len(rows)):
            selected = 0  # a phase is always selected so detail is never empty
        if selected is not None and selected < len(rows):
            view.index = selected

    def _refresh_detail(self) -> None:
        phase_id = self._selected_phase_id()
        self.query_one("#detail").update(self.board.detail(phase_id) if phase_id else "")

    def _selected_phase_id(self) -> str | None:
        phases = self.board.phases()
        index = self.query_one("#rail", ListView).index
        if index is None or not 0 <= index < len(phases):
            return None
        return phases[index][1]

    def _append_log(self) -> None:
        lines = self.board.log_tail(_LOG_WINDOW)  # bounded, unlike the board's log
        # `lines` is a sliding window: once the board outgrows it, the window
        # shifts one line per event, so only the not-yet-written tail is new.
        skip = len(lines) - (self._events_seen - self.log_lines_rendered)
        for line in lines[max(skip, 0):]:
            self.query_one("#log", RichLog).write(line)
        self.log_lines_rendered = self._events_seen

    def on_list_view_selected(self, event) -> None:
        """Click/Enter on the rail moves the detail pane."""
        if event.control is self.query_one("#rail"):
            self._refresh_detail()

    def on_list_view_highlighted(self, event) -> None:
        """Arrow keys highlight a rail row; the detail pane follows it too."""
        if event.control is self.query_one("#rail"):
            self._refresh_detail()

    # ------------------------------------------------------------- actions

    def action_copy_command(self) -> None:
        self.copy_to_clipboard(self.command)
        self.notify(f"copied: {self.command}")

    def action_toggle_about(self) -> None:
        about = self.query_one("#about")
        about.display = not about.display

    async def action_quit(self) -> None:
        self.stop_event.set()  # release a blocked follow() in the pump thread
        await super().action_quit()  # textual 8: action_quit is a coroutine

    def on_unmount(self) -> None:
        self.stop_event.set()


# ------------------------------------------------------- source resolution

def run_flow(argv: list[str]) -> int:
    """`wpbuddy flow` — resolve the event source, show the observatory."""
    parser = argparse.ArgumentParser(
        prog="wpbuddy flow",
        description="Single-screen flow observatory: watch a scan live or replay a run.")
    parser.add_argument("--target", help="scan this URL now and tail its new run log")
    parser.add_argument("--run", metavar="PATH",
                        help="replay this events.jsonl (or the run directory holding it)")
    # every other flag (e.g. --profile, --stealth, --audit-code, --pluginList,
    # --json, --max-pages, --offline, --output) is forwarded to the scan
    # subprocess verbatim; only --run is flow's own.
    args, passthrough = parser.parse_known_args(argv)

    events_path = None
    proc = None
    command = None
    target = None
    host = None
    profile = _profile_from(passthrough)

    if args.run:
        events_path = _resolve_run_path(args.run)
        if events_path is None:
            print(f"run log not found: {args.run} - pass --target to start a new scan "
                  f"or --run with a recorded run directory or events.jsonl file")
            return 2
    elif args.target:
        host = urlsplit(args.target).hostname
        if not host:
            print(f"target must be a URL with a host: {args.target}")
            return 2
    else:
        events_path = _newest_events_file(Path("wpbuddy-audit"))
        if events_path is None:
            print("no recorded runs found - pass --target or --run")
            return 2

    if not textual_available():
        print("the flow screen needs Textual - install it with: pip install 'wpbuddy[tui]'")
        return 2

    if args.run or not args.target:
        target = _target_label(events_path)
    else:
        target = host

    stop_event = threading.Event()
    if args.target and not args.run:  # --run wins: replay, never spawn
        spawn_cmd = [sys.executable, "-m", "wpbuddy.cli", "scan",
                     "--target", args.target, *passthrough]
        command = " ".join(shlex.quote(part) for part in spawn_cmd)
        events_path, proc = _spawn_and_locate(spawn_cmd, host)
        if events_path is None:
            if proc.poll() is not None:
                print("the scan ended without writing a run log (--no-run-log or --plan?)")
                return proc.returncode or 0
            print("the scan did not create a run log - stopping it")
            _stop_child(proc)
            return 1

        def source():
            return follow(events_path, stop_event)
    else:

        def source():
            return replay(events_path)

    if command is None:  # a recorded run: the spawn command is unknown
        command = f"wpbuddy flow --run {events_path}"

    app = FlowApp(source=source, board=ScanBoard(), command=command,
                  target=target, profile=profile or "safe", stop_event=stop_event)
    app.run()

    if proc is None:
        return 0
    if proc.poll() is not None:  # the scan finished before the app exited
        return proc.returncode if proc.returncode is not None else 0
    _stop_child(proc)  # the operator quit while the scan was still running
    return 0


def _resolve_run_path(raw) -> Path | None:
    """events.jsonl for a --run argument: the file itself, or inside a directory."""
    path = Path(raw)
    if path.is_file():
        return path
    if path.is_dir():
        inside = path / "events.jsonl"
        return inside if inside.is_file() else None
    return None


def _newest_events_file(root: Path) -> Path | None:
    """The newest events.jsonl across every host's runs under the audit root."""
    candidates = [p for p in root.glob("*/runs/*/events.jsonl") if p.is_file()]
    return max(candidates, key=lambda p: p.stat().st_mtime_ns) if candidates else None


def _spawn_and_locate(spawn_cmd, host):
    """Start the scan subprocess, then wait for its NEW run log to appear."""
    runs_root = Path("wpbuddy-audit") / (host or "target") / "runs"
    known = {str(p) for p in runs_root.glob("*/events.jsonl")}
    # POSIX only (macOS/Linux are the targets): the child starts its own
    # session, so it leads a process group a quit-time SIGINT can reach
    # wholesale - the scanner and anything it spawned.
    proc = subprocess.Popen(spawn_cmd, start_new_session=True)
    deadline = time.monotonic() + _RUN_APPEAR_TIMEOUT
    while True:
        candidates = [p for p in runs_root.glob("*/events.jsonl")
                      if p.is_file() and str(p) not in known]
        if candidates:
            return max(candidates, key=lambda p: p.stat().st_mtime_ns), proc
        if proc.poll() is not None or time.monotonic() >= deadline:
            return None, proc
        time.sleep(_POLL_INTERVAL)


def _stop_child(proc) -> None:
    """SIGINT the scan's process group, wait out the grace period, SIGKILL."""
    if proc.poll() is not None:
        return
    _signal_group(proc, signal.SIGINT)
    deadline = time.monotonic() + _INTERRUPT_GRACE
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            return
        time.sleep(_POLL_INTERVAL)
    _signal_group(proc, signal.SIGKILL)
    proc.wait()


def _signal_group(proc, sig) -> None:
    """Signal the child's whole process group (it is its own session leader)."""
    try:
        os.killpg(proc.pid, sig)
    except OSError:
        try:
            proc.send_signal(sig)  # group already gone, or a non-POSIX host
        except OSError:
            pass


def _target_label(events_path: Path) -> str:
    """Top-bar target for a recorded run: meta.json's target, else its host dir."""
    try:
        meta = json.loads((events_path.parent / "meta.json").read_text(encoding="utf-8"))
        target = meta.get("target")
    except (OSError, ValueError, AttributeError):
        target = None
    if target:
        return urlsplit(str(target)).hostname or str(target)
    parts = events_path.parent.parts  # .../wpbuddy-audit/<host>/runs/<run_id>
    if len(parts) >= 3 and parts[-2] == "runs":
        return parts[-3]
    return "recorded run"


def _profile_from(argv: list[str]) -> str | None:
    """The --profile the operator passed through to the scan, if any."""
    for index, arg in enumerate(argv):
        if arg == "--profile" and index + 1 < len(argv):
            return argv[index + 1]
        if arg.startswith("--profile="):
            return arg.split("=", 1)[1]
    return None
