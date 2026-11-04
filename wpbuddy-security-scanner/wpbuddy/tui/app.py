"""The Textual shell of the flow screen: `wpbuddy flow`.

This is the only module anywhere in the package that imports Textual, and
it does so behind a guard so everything else keeps working when the extra
is missing: `textual_available()` answers through `importlib.util.find_spec`
(it never imports Textual), `FlowApp` subclasses the real App when the
extra is installed and a bare placeholder otherwise, and `run_flow()` bails
with an install hint before building any UI.

Two surfaces, one app: `LauncherScreen` (the entry screen `wpbuddy flow`
with no arguments opens — pick a target and functionalities, or open a
previous run) hands off to `ObservatoryScreen` (the single observation
surface: top bar, phase rail, phase detail, findings, event log — no
modes). `?` overlays the about pane, `c` copies the command that produced
the current state, `q` quits (interrupting a live scan with SIGINT to its
process group first).

`run_flow` resolves the event source: `--run PATH` replays a recorded run,
`--target URL` spawns a scan and tails its new run log, and anything else
opens the launcher.
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

from .. import config
from ..runs.store import audit_root
from .art import LOGO
from .render import ScanBoard
from .tail import follow, replay

try:  # the 'tui' extra; without it FlowApp stays importable but unusable
    from textual.app import App
    from textual.binding import Binding
    from textual.containers import Horizontal, Vertical
    from textual.css.query import NoMatches
    from textual.screen import Screen
    from textual.widgets import Button, Checkbox, Input, Label, ListItem, ListView, RichLog, Static
except ImportError:  # pragma: no cover - only reachable without the extra
    App = object  # type: ignore[assignment,misc]
    Binding = tuple  # type: ignore[assignment,misc]  # inert placeholder
    NoMatches = Exception  # type: ignore[assignment,misc]
    Screen = object  # type: ignore[assignment,misc]

# Key hints for the footers; the about pane repeats the observatory's.
HINTS = "↑↓ phases  ?: about  q quit  c copy CLI"
LAUNCHER_HINTS = "enter launch  ↑↓+enter open run  c copy CLI  q quit"
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
# Signals that kill the TUI without Python unwind; guarded to POSIX.
_GUARD_SIGNALS = tuple(getattr(signal, name) for name in ("SIGHUP", "SIGTERM")
                       if hasattr(signal, name))
# Phase-lifecycle events are the only ones that change a rail row's glyph.
_PHASE_EVENTS = ("phase-started", "phase-finished", "phase-skipped", "phase-failed")
# Events that move the top bar's numbers (requests count / run status).
_TOPBAR_EVENTS = ("http-response", "run-started", "run-finished")


def textual_available() -> bool:
    """True when the textual extra is importable; never imports it."""
    return importlib.util.find_spec("textual") is not None


class FlowApp(App):
    """The flow app: an optional LauncherScreen entry, then the observatory."""

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
    LauncherScreen #options { height: auto; }
    LauncherScreen #cycles { height: 3; }
    LauncherScreen #previous { height: 1fr; border: round $panel; }
    """
    BINDINGS = [
        Binding("q", "quit", "quit"),
        Binding("c", "copy_command", "copy CLI"),
        Binding("question_mark", "toggle_about", "about"),
    ]

    def __init__(self, source=None, board=None, command="", target="scan",
                 profile="safe", stop_event=None, launcher=False, runs_dir=None):
        super().__init__()
        self._source = source  # zero-arg callable returning an event iterator
        self._launcher = launcher
        self._pump_started = False
        self.launched_proc = None  # set when the launcher spawns a scan
        self.runs_dir = runs_dir  # explicit --runs-dir: list + spawn follow it
        self.board = board if board is not None else ScanBoard()
        self.command = command  # what `c` copies: the spawn cmd / replay cmd
        self.target = target
        self.profile = profile
        self.stop_event = stop_event if stop_event is not None else threading.Event()
        self.source_done = threading.Event()  # set once the source is drained
        self.log_lines_rendered = 0  # log pane appends only lines it has not shown
        self._events_seen = 0  # one board log line exists per applied event
        self._rail_dirty = True  # first paint renders everything
        self._findings_dirty = True
        self._topbar_dirty = True

    def get_default_screen(self):
        """The launcher for no-arg flow; the observatory for --run/--target."""
        if self._launcher:
            return LauncherScreen()
        return ObservatoryScreen()

    def _start_pump(self) -> None:
        """Start the event pump once, when an observatory screen mounts."""
        if self._pump_started or self._source is None:
            return
        self._pump_started = True
        threading.Thread(target=self._pump_source, daemon=True).start()

    def _observatory_ready(self) -> None:
        """The observatory screen is current: paint it and start the pump."""
        self.refresh_panes()
        self._start_pump()

    def _launch_root(self) -> Path:
        """The root a launcher session lists from and records into."""
        return self.runs_dir if self.runs_dir is not None else runs_root()

    def _observatory(self):
        """The mounted observatory screen, if any (there is at most one).

        App-level queries root at the DEFAULT screen, which for no-arg flow
        is the launcher - pane widgets live on the observatory screen, so
        every pane query must be scoped there.
        """
        for screen in reversed(self.screen_stack):
            if isinstance(screen, ObservatoryScreen):
                return screen
        return None

    def _pane(self, selector, expect_type=None):
        """query_one scoped to the observatory screen (NoMatches if not up)."""
        screen = self._observatory()
        if screen is None:
            raise NoMatches(selector)
        if expect_type is None:
            return screen.query_one(selector)
        return screen.query_one(selector, expect_type)

    # ------------------------------------------------------ launcher handoff

    def launch_scan(self, target_value: str, flags: list[str]) -> None:
        """Spawn a scan from the launcher's state, then show the observatory."""
        host = urlsplit(target_value).hostname if target_value else None
        if not host:
            self.notify("target must be a URL with a host (https://example.com/)",
                        markup=False, severity="error")
            return
        spawn_cmd = [sys.executable, "-m", "wpbuddy.cli", "scan", *flags]
        events_path, proc = _spawn_and_locate(spawn_cmd, host, self._launch_root())
        self.launched_proc = proc
        if events_path is None:
            if proc.poll() is not None:
                self.notify("the scan ended without writing a run log "
                            "(--no-run-log or --plan?)", markup=False, severity="error")
            else:
                self.notify("the scan did not create a run log - stopping it",
                            markup=False, severity="error")
                _stop_child(proc)
            return  # stay on the launcher: the operator can adjust and retry
        self.target = host
        self.profile = _profile_from(flags) or "safe"
        self.command = "wpbuddy scan " + " ".join(shlex.quote(part) for part in flags)
        self._source = lambda: follow(events_path, self.stop_event)
        # push (not switch): textual 8.2.8's switch_screen pops a result
        # callback the default screen never got - push keeps the launcher
        # beneath, and nothing binds a way back to it.
        self.push_screen(ObservatoryScreen())

    def open_run(self, events_path: Path) -> None:
        """Replay a recorded run (picked on the launcher) in the observatory."""
        meta = _read_meta(events_path)
        self.target = _target_label(events_path, meta)
        self.profile = _profile_from([str(part) for part in (meta.get("argv") or [])]) \
            or "safe"
        self.command = f"wpbuddy flow --run {events_path}"
        self._source = lambda: replay(events_path)
        self.push_screen(ObservatoryScreen())  # see launch_scan: push, not switch

    # -------------------------------------------------------------- events

    def apply_event(self, event: dict) -> None:
        """Fold one event into the board; mark the panes it can change dirty."""
        self.board.apply(event)
        self._events_seen += 1
        event_type = event.get("type") or ""
        if event_type in _PHASE_EVENTS:
            self._rail_dirty = True
        if event_type == "finding":
            self._findings_dirty = True
        if event_type in _TOPBAR_EVENTS:
            self._topbar_dirty = True
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
        # screen-scoped: in launcher sessions the observatory is a pushed
        # screen, and app-level queries root at the (launcher) default screen
        self._pane("#log", RichLog).write(f"[!] event source failed: {exc}")

    # ------------------------------------------------------------ refresh

    def refresh_panes(self) -> None:
        """Re-render only dirty panes; a no-op until they are mounted."""
        try:
            self._refresh_panes()
        except NoMatches:
            return  # the observatory screen is not current yet (launcher handoff)

    def _refresh_panes(self) -> None:
        """Re-render only dirty panes (the log always appends just new lines)."""
        if self._topbar_dirty:
            stats = self.board.stats()
            self._pane("#topbar").update(
                f"target {self.target} · profile {self.profile} · "
                f"requests {stats['requests']} · status {stats['status']}")
            self._topbar_dirty = False
        if self._rail_dirty:
            self._rebuild_list("#rail", [f"{glyph} {phase_id} {title}"
                                         for glyph, phase_id, title in self.board.phases()])
            self._rail_dirty = False
            self._refresh_detail()  # a rebuilt rail can change the selected phase's text
        if self._findings_dirty:
            self._rebuild_list("#findings", [f"{label} — {name}"
                                             for label, name in self.board.findings()])
            self._findings_dirty = False
        self._append_log()

    def _rebuild_list(self, selector: str, rows: list[str]) -> None:
        """Swap a ListView's items, keeping the operator's selection."""
        view = self._pane(selector, ListView)
        selected = view.index
        view.clear()
        view.extend([ListItem(Label(row, markup=False)) for row in rows])
        if selector == "#rail" and len(rows) and (selected is None or selected >= len(rows)):
            selected = 0  # a phase is always selected so detail is never empty
        if selected is not None and selected < len(rows):
            view.index = selected

    def _refresh_detail(self) -> None:
        phase_id = self._selected_phase_id()
        self._pane("#detail").update(self.board.detail(phase_id) if phase_id else "")

    def _selected_phase_id(self) -> str | None:
        phases = self.board.phases()
        index = self._pane("#rail", ListView).index
        if index is None or not 0 <= index < len(phases):
            return None
        return phases[index][1]

    def _append_log(self) -> None:
        lines = self.board.log_tail(_LOG_WINDOW)  # bounded, unlike the board's log
        # `lines` is a sliding window: once the board outgrows it, the window
        # shifts one line per event, so only the not-yet-written tail is new.
        skip = len(lines) - (self._events_seen - self.log_lines_rendered)
        for line in lines[max(skip, 0):]:
            self._pane("#log", RichLog).write(line)
        self.log_lines_rendered = self._events_seen

    def on_list_view_selected(self, event) -> None:
        """Click/Enter on the rail moves the detail pane."""
        if self._observatory() is None:  # the launcher is up: no rail to follow
            return
        if event.control is self._pane("#rail", ListView):
            self._refresh_detail()

    def on_list_view_highlighted(self, event) -> None:
        """Arrow keys highlight a rail row; the detail pane follows it too."""
        if self._observatory() is None:  # the launcher is up: no rail to follow
            return
        if event.control is self._pane("#rail", ListView):
            self._refresh_detail()

    # ------------------------------------------------------------- actions

    def action_copy_command(self) -> None:
        self.copy_to_clipboard(self.command)
        self.notify(f"copied: {self.command}", markup=False)  # operator input, not markup

    def action_toggle_about(self) -> None:
        try:
            about = self._pane("#about")
        except NoMatches:  # no observatory (or its panes) up: nothing to toggle
            return
        about.display = not about.display

    async def action_quit(self) -> None:
        self.stop_event.set()  # release a blocked follow() in the pump thread
        await super().action_quit()  # textual 8: action_quit is a coroutine

    def on_unmount(self) -> None:
        self.stop_event.set()


class ObservatoryScreen(Screen):
    """The observation surface: every pane always mounted, no modes."""

    def compose(self):
        app = self.app
        yield Static(f"{LOGO.splitlines()[0]}  WpBuddy Flow — {app.target}",
                     id="header", markup=False)
        yield Static("", id="topbar", markup=False)
        with Horizontal(id="mid"):
            yield ListView(id="rail")
            with Vertical(id="right"):
                yield Static("", id="detail", markup=False)
                yield ListView(id="findings")
        yield RichLog(max_lines=_LOG_WINDOW, id="log")  # bounded retention
        yield Static(ABOUT_TEXT, id="about", markup=False)
        yield Static(HINTS, id="footer", markup=False)

    def on_mount(self) -> None:
        self.query_one("#about").display = False  # overlay pane, hidden until `?`
        self.query_one("#rail", ListView).border_title = "phases"
        self.query_one("#detail", Static).border_title = "phase detail"
        self.query_one("#findings", ListView).border_title = "findings"
        self.query_one("#log", RichLog).border_title = "event log"
        self.query_one("#rail", ListView).focus()  # ↑↓ drive the rail out of the box
        # App-level queries root at the CURRENT screen; while this screen is
        # being pushed the launcher is still current, so defer app work until
        # this screen actually is.
        self.call_after_refresh(self.app._observatory_ready)


class LauncherScreen(Screen):
    """The entry screen: pick a target + functionalities, or open a previous run.

    Controls map 1:1 onto existing CLI flags (no scan behavior lives here):
    the built argv is exactly the final control states, untoggled flags
    absent, cycle controls emitting their flag only once off the CLI default.
    """

    AUDIT_MODES = ("off", "source", "target", "auto")  # CLI default: auto
    FAIL_GATES = ("none", "critical", "high", "medium", "any")  # CLI default: none

    def __init__(self):
        super().__init__()
        self.runs: list[Path] = []  # events.jsonl per row, newest first
        self.audit_mode = "auto"
        self.fail_gate = "none"

    def compose(self):
        yield Static(f"{LOGO.splitlines()[0]}  WpBuddy Flow — launcher",
                     id="header", markup=False)
        yield Input(placeholder="https://target.example.com/", id="target")
        with Vertical(id="options"):
            yield Checkbox("Deep discovery  (--profile deep)", id="deep")
            yield Checkbox("Slug enumeration  (--enum-plugins)", id="enum")
            yield Checkbox("Credential test  (--access)", id="access")
            yield Checkbox("Verify PoCs  (--verify-pocs)", id="verify")
            yield Checkbox("JSON graph  (--json)", id="json")
        with Horizontal(id="cycles"):
            yield Button("audit: auto", id="audit-code")
            yield Button("fail-on: none", id="fail-on")
            yield Button("Launch scan", id="launch", variant="primary")
        yield ListView(id="previous")
        yield Static(LAUNCHER_HINTS, id="footer", markup=False)

    def on_mount(self) -> None:
        self.query_one("#previous", ListView).border_title = "previous runs"
        self._refresh_runs()
        self.query_one("#target", Input).focus()
        self._sync_command()  # `c` copies `wpbuddy scan` from the very start

    def _refresh_runs(self) -> None:
        """List every run under the launch root, newest first (or empty state)."""
        view = self.query_one("#previous", ListView)
        runs = _recorded_runs(self.app._launch_root())
        self.runs = [path for path, _count in runs]
        if runs:
            items = [ListItem(Label(_run_label(path, count), markup=False))
                     for path, count in runs]
        else:
            items = [ListItem(Label("no previous runs", markup=False))]
        view.extend(items)

    # -------------------------------------------------------- argv building

    def built_argv(self) -> list[str]:
        """The copyable `wpbuddy scan ...` argv, exactly from control states."""
        argv = ["wpbuddy", "scan"]
        target = self.query_one("#target", Input).value.strip()
        if target:
            argv += ["--target", target]
        for checkbox_id, flags in (("deep", ("--profile", "deep")),
                                   ("enum", ("--enum-plugins",)),
                                   ("access", ("--access",)),
                                   ("verify", ("--verify-pocs",)),
                                   ("json", ("--json",))):
            if self.query_one(f"#{checkbox_id}", Checkbox).value:
                argv += list(flags)
        if self.audit_mode != "auto":  # at the CLI default: absent
            argv += ["--audit-code", self.audit_mode]
        if self.fail_gate != "none":  # at the CLI default: absent
            argv += ["--fail-on", self.fail_gate]
        if self.app.runs_dir is not None:  # honor the session's --runs-dir
            argv += ["--runs-dir", str(self.app.runs_dir)]
        return argv

    def _sync_command(self) -> None:
        """Keep the `c`-copyable command in lockstep with the controls."""
        self.app.command = " ".join(shlex.quote(part) for part in self.built_argv())

    # -------------------------------------------------------------- events

    def on_input_changed(self, event) -> None:
        if event.control is self.query_one("#target", Input):
            self._sync_command()

    def on_checkbox_changed(self, event) -> None:
        self._sync_command()

    def on_input_submitted(self, event) -> None:
        if event.control is self.query_one("#target", Input):
            self._launch()

    def on_button_pressed(self, event) -> None:
        button = event.button
        if button.id == "audit-code":
            self._cycle("audit_mode", self.AUDIT_MODES, button, "audit: ")
        elif button.id == "fail-on":
            self._cycle("fail_gate", self.FAIL_GATES, button, "fail-on: ")
        elif button.id == "launch":
            self._launch()

    def on_list_view_selected(self, event) -> None:
        if event.control is self.query_one("#previous", ListView):
            event.stop()  # the observatory's rail handler must not see this
            view = self.query_one("#previous", ListView)
            if view.index is not None and 0 <= view.index < len(self.runs):
                self.app.open_run(self.runs[view.index])

    # ------------------------------------------------------------- actions

    def _cycle(self, attribute, values, button, prefix) -> None:
        current = getattr(self, attribute)
        setattr(self, attribute, values[(values.index(current) + 1) % len(values)])
        button.label = f"{prefix}{getattr(self, attribute)}"
        self._sync_command()

    def _launch(self) -> None:
        self.app.launch_scan(self.query_one("#target", Input).value.strip(),
                             self.built_argv()[2:])  # drop the "wpbuddy scan" words


# ------------------------------------------------------- source resolution

def run_flow(argv: list[str]) -> int:
    """`wpbuddy flow` — resolve the event source, show the observatory."""
    parser = argparse.ArgumentParser(
        prog="wpbuddy flow",
        description="Single-screen flow observatory: watch a scan live or replay a run.")
    parser.add_argument("--target", help="scan this URL now and tail its new run log")
    parser.add_argument("--run", metavar="PATH",
                        help="replay this events.jsonl (or the run directory holding it)")
    # passthrough flags are forwarded verbatim to the scan when --target
    # spawns one; in launcher mode only --runs-dir is honored (the launcher's
    # controls own every other flag) and the rest get a one-line notice.
    args, passthrough = parser.parse_known_args(argv)

    if not textual_available():
        print("the flow screen needs Textual - install it with: pip install 'wpbuddy[tui]'")
        return 2

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
        meta = _read_meta(events_path)
        target = _target_label(events_path, meta)
        profile = profile or _profile_from([str(part) for part in (meta.get("argv") or [])])
    elif args.target:
        host = urlsplit(args.target).hostname
        if not host:
            print(f"target must be a URL with a host: {args.target}")
            return 2
        target = host
    # no --run/--target: the launcher picks the source interactively

    stop_event = threading.Event()
    if args.target and not args.run:  # --run wins: replay, never spawn
        spawn_cmd = [sys.executable, "-m", "wpbuddy.cli", "scan",
                     "--target", args.target, *passthrough]
        command = " ".join(shlex.quote(part) for part in spawn_cmd)
        # the child resolves --runs-dir itself (config.RUNS_DIR in its own
        # process); audit_root() expands `~`, so the watcher follows the
        # SAME root the child will write to.
        root = audit_root(_flag_value(passthrough, "--runs-dir"))
        events_path, proc = _spawn_and_locate(spawn_cmd, host, root)
        if events_path is None:
            if proc.poll() is not None:
                print("the scan ended without writing a run log (--no-run-log or --plan?)")
                return max(proc.returncode or 0, 0)
            print("the scan did not create a run log - stopping it")
            _stop_child(proc)
            return 1

        def source():
            return follow(events_path, stop_event)

        app = FlowApp(source=source, board=ScanBoard(), command=command,
                      target=target, profile=profile or "safe", stop_event=stop_event)
    elif args.run:

        def source():
            return replay(events_path)

        app = FlowApp(source=source, board=ScanBoard(),
                      command=f"wpbuddy flow --run {events_path}",
                      target=target, profile=profile or "safe", stop_event=stop_event)
    else:  # the entry screen: launcher picks a target or a previous run
        raw_runs_dir = _flag_value(passthrough, "--runs-dir")
        if raw_runs_dir:  # the previous-runs list and every launch follow it
            config.RUNS_DIR = Path(raw_runs_dir).expanduser()
        ignored = _strip_flag(passthrough, "--runs-dir")
        if ignored:
            print("[!] ignoring passthrough flag(s) in launcher mode "
                  "(the launcher controls them): " + " ".join(ignored))
        app = FlowApp(launcher=True, board=ScanBoard(), stop_event=stop_event,
                      runs_dir=Path(raw_runs_dir).expanduser() if raw_runs_dir else None)

    # The scan must never outlive the TUI: stop the child on every exit path
    # (normal return, a textual crash, an exception) and on terminal-closing
    # signals, which otherwise kill the TUI without Python-level unwinding.
    # The ref covers a child the launcher spawns mid-run, too.
    guard = _ChildGuard(
        lambda: proc if proc is not None else getattr(app, "launched_proc", None)
    ).install()
    try:
        app.run()
    finally:
        guard.close()
    proc = proc if proc is not None else getattr(app, "launched_proc", None)
    if proc is None:
        return 0
    return max(proc.returncode or 0, 0)  # clamp signal deaths (-9/-15) to 0


def _resolve_run_path(raw) -> Path | None:
    """events.jsonl for a --run argument: the file itself, or inside a directory."""
    path = Path(raw)
    if path.is_file():
        return path
    if path.is_dir():
        inside = path / "events.jsonl"
        return inside if inside.is_file() else None
    return None


def runs_root() -> Path:
    """Where scans record runs: the store's own audit root, nothing re-derived
    (explicit base wins, then config.RUNS_DIR, else the legacy CWD root)."""
    return audit_root()


def _recorded_runs(root: Path) -> list[tuple[Path, int]]:
    """Every run's (events.jsonl, event count) under the root, newest first.

    Counting lines (not parsing JSON) keeps this cheap for long runs; the
    launcher only needs a number for the row label.
    """
    runs = []
    for path in root.glob("*/runs/*/events.jsonl"):
        if not path.is_file():
            continue
        try:
            with open(path, "rb") as fh:
                runs.append((path, sum(1 for _ in fh)))
        except OSError:
            continue
    return sorted(runs, key=lambda run: run[0].stat().st_mtime_ns, reverse=True)


def _run_label(events_path: Path, count: int) -> str:
    """One previous-runs row: `YYYYmmdd-HHMMSS  <host>  <N> events`."""
    stamp = "-".join(events_path.parent.name.split("-")[:2])
    host = events_path.parent.parent.parent.name
    return f"{stamp}  {host}  {count} events"


def _spawn_and_locate(spawn_cmd, host, root=None):
    """Start the scan subprocess, then wait for its NEW run log to appear."""
    base = root if root is not None else runs_root()
    host_runs = base / (host or "target") / "runs"
    known = {str(p) for p in host_runs.glob("*/events.jsonl")}
    # POSIX only (macOS/Linux are the targets): the child starts its own
    # session, so it leads a process group a quit-time SIGINT can reach
    # wholesale - the scanner and anything it spawned.
    proc = subprocess.Popen(spawn_cmd, start_new_session=True)
    deadline = time.monotonic() + _RUN_APPEAR_TIMEOUT
    while True:
        candidates = [p for p in host_runs.glob("*/events.jsonl")
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


class _ChildGuard:
    """Best-effort guarantee a spawned scan dies with the TUI.

    `close()` runs from run_flow's finally (any exit path); SIGHUP/SIGTERM
    (a closed terminal kills the TUI without Python unwind) stop the child
    too, then exit with the conventional 128+signum code. Signal handlers
    are installed only in the main thread and restored on close. `proc` may
    be a Popen-like object or a callable returning one, so a child the
    launcher spawns mid-run is covered too.
    """

    def __init__(self, proc):
        self._proc = proc
        self._previous: dict = {}

    @property
    def proc(self):
        return self._proc() if callable(self._proc) else self._proc

    def install(self) -> _ChildGuard:
        for sig in _GUARD_SIGNALS:  # installed even before any child exists:
            try:  # the launcher may spawn one mid-run
                self._previous[sig] = signal.signal(sig, self._handle)
            except (ValueError, OSError):  # not the main thread / unsupported
                pass
        return self

    def _handle(self, signum, frame) -> None:
        proc = self.proc
        if proc is not None and proc.poll() is None:
            _stop_child(proc)
        raise SystemExit(128 + signum)

    def close(self) -> None:
        for sig, previous in self._previous.items():
            try:
                signal.signal(sig, previous)
            except (ValueError, OSError):
                pass
        self._previous.clear()
        proc = self.proc
        if proc is not None and proc.poll() is None:
            _stop_child(proc)


def _read_meta(events_path: Path) -> dict:
    """The run's meta.json as a dict ({} when absent or unreadable)."""
    try:
        meta = json.loads((events_path.parent / "meta.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return meta if isinstance(meta, dict) else {}


def _target_label(events_path: Path, meta: dict | None = None) -> str:
    """Top-bar target for a recorded run: meta.json's target, else its host dir."""
    target = (meta if meta is not None else _read_meta(events_path)).get("target")
    if target:
        return urlsplit(str(target)).hostname or str(target)
    parts = events_path.parent.parts  # .../wpbuddy-audit/<host>/runs/<run_id>
    if len(parts) >= 3 and parts[-2] == "runs":
        return parts[-3]
    return "recorded run"


def _flag_value(argv: list[str], flag: str) -> str | None:
    """The value of `flag`/`flag=value` in an argv list, if present."""
    for index, arg in enumerate(argv):
        if arg == flag and index + 1 < len(argv):
            return argv[index + 1]
        if arg.startswith(flag + "="):
            return arg.split("=", 1)[1]
    return None


def _strip_flag(argv: list[str], flag: str) -> list[str]:
    """argv without every `flag value`/`flag=value` occurrence of one flag."""
    rest = []
    skip_value = False
    for arg in argv:
        if skip_value:
            skip_value = False
            continue
        if arg == flag:
            skip_value = True
            continue
        if arg.startswith(flag + "="):
            continue
        rest.append(arg)
    return rest


def _profile_from(argv: list[str]) -> str | None:
    """The --profile the operator passed through to the scan, if any."""
    return _flag_value(argv, "--profile")
