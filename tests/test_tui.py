"""Unit tests for the TUI's event plumbing: board and event sources.

The board (`wpbuddy.tui.render`) folds event dicts shaped like
`Event.to_dict()` (see `wpbuddy.engine.events`) into pane models: phase-rail
glyphs, phase detail text, findings, a formatted log tail and top-bar stats.
The sources (`wpbuddy.tui.tail`) read those event dicts out of a run's
`events.jsonl`, live or recorded. Both are pure stdlib — no Textual — so
everything here is unit-testable without a terminal.
"""

import ast
import asyncio
import json
import os
import signal
import sys
import threading
import time
from pathlib import Path

import pytest

from wpbuddy.engine.phases import PhaseSpec, default_graph
from wpbuddy.tui.render import ScanBoard
from wpbuddy.tui.tail import follow, read_events, replay

TS = "2026-11-04T12:00:00.000+00:00"


def _event(event_type, phase=None, seq=0, ts=TS, **data):
    """An event dict exactly as `Event.to_dict()` shapes it."""
    return {"seq": seq, "ts": ts, "type": event_type, "phase": phase,
            "data": data}


def _script():
    """One short recorded run: liveness+passive done, deep-discovery skipped."""
    return [
        _event("run-started", seq=1, ts="2026-11-04T12:00:00.000+00:00",
               target="acme.test"),
        _event("phase-started", "liveness", seq=2),
        _event("phase-finished", "liveness", seq=3),
        _event("phase-started", "passive", seq=4),
        _event("phase-finished", "passive", seq=5),
        _event("phase-skipped", "deep-discovery", seq=6,
               reasons=["aggressive discovery needs --profile deep"]),
        _event("http-response", "passive", seq=7, url="http://acme.test/", status=200),
        _event("http-response", "passive", seq=8, url="http://acme.test/readme.html", status=200),
        _event("finding", "passive", seq=9, name="readme.html exposed", severity="low"),
        _event("run-finished", seq=10, ts="2026-11-04T12:04:00.000+00:00", status="completed"),
    ]


def _scripted_board():
    board = ScanBoard()
    for event in _script():
        board.apply(event)
    return board


# --------------------------------------------------------------- phase rail

def test_rail_lists_every_graph_phase_in_order_with_glyphs():
    board = _scripted_board()
    rows = board.phases()
    assert [phase_id for _, phase_id, _ in rows][:3] == \
        ["liveness", "passive", "deep-discovery"]
    glyphs = [glyph for glyph, _, _ in rows]
    # first three phases: two finished, one skipped (with its reason below)
    assert glyphs[:3] == ["✓", "✓", "⊘"]
    # phases without events are still on the rail, pending
    assert glyphs[3] == "·"
    assert [title for _, _, title in rows][:3] == \
        ["Liveness", "Passive recon", "Aggressive discovery"]


def test_skipped_phase_carries_its_reason():
    board = _scripted_board()
    assert "⊘" in board.detail("deep-discovery")
    assert "aggressive discovery needs --profile deep" in board.detail("deep-discovery")


def test_phase_glyph_transitions_running_and_failed():
    board = ScanBoard()
    board.apply(_event("phase-started", "active"))
    assert board.phases()[3][0] == "▸"  # active is the 4th phase
    board.apply(_event("phase-failed", "active", message="boom: nope"))
    assert board.phases()[3][0] == "!"
    assert "boom: nope" in board.detail("active")


def test_board_accepts_an_explicit_graph():
    graph = [PhaseSpec("a", "Alpha", "do a", handler="a"),
             PhaseSpec("b", "Beta", "do b", handler="b", effects=())]
    board = ScanBoard(graph=graph)
    assert board.phases() == [("·", "a", "Alpha"), ("·", "b", "Beta")]


# ------------------------------------------------------------------- detail

def test_detail_contains_purpose_preconditions_and_effects():
    board = _scripted_board()
    text = board.detail("passive")
    assert "GET-only recon: core/theme/plugin inventory, " \
        "exposure and vulnerability matching" in text
    assert "the liveness probe reached the target" in text  # precondition
    assert "network" in text  # effects


def test_detail_for_phase_without_preconditions_or_unknown_id():
    board = ScanBoard()
    assert "none" in board.detail("liveness").lower()
    assert board.detail("not-a-phase") == ""


# ----------------------------------------------------------------- findings

def test_findings_pair_severity_label_with_name():
    board = _scripted_board()
    assert ("LOW", "readme.html exposed") in board.findings()
    assert ScanBoard().findings() == []


# ---------------------------------------------------------------- log lines

def test_log_tail_has_one_line_per_event_and_formats_ts_phase_summary():
    board = _scripted_board()
    lines = board.log_tail()
    assert len(lines) == len(_script())
    for line in lines:
        assert line.startswith("[2026-11-04T")
        assert "] [" in line
    assert "aggressive discovery needs --profile deep" in lines[5]
    assert board.log_tail(2) == lines[-2:]
    assert board.log_tail(0) == []


# -------------------------------------------------------------------- stats

def test_stats_count_responses_and_run_window():
    board = _scripted_board()
    stats = board.stats()
    assert stats["requests"] == 2
    assert stats["started_ts"] == "2026-11-04T12:00:00.000+00:00"
    assert stats["finished_ts"] == "2026-11-04T12:04:00.000+00:00"
    assert stats["status"] == "completed"


def test_stats_of_a_fresh_board_are_empty_and_pending():
    stats = ScanBoard().stats()
    assert stats["status"] == "pending"
    assert stats["requests"] == 0
    assert stats["started_ts"] is None
    assert stats["finished_ts"] is None


# ------------------------------------------------------- robustness at edges

def test_event_for_unknown_phase_does_not_crash_or_add_rail_row():
    board = ScanBoard()
    before = board.phases()
    board.apply(_event("phase-started", "ghost-phase"))
    board.apply(_event("phase-skipped", "ghost-phase", reasons=["whatever"]))
    assert board.phases() == before  # no rail row added, nothing crashed


def test_unknown_event_type_is_recorded_without_crashing():
    board = ScanBoard()
    board.apply(_event("future-thing", "passive", detail="hello"))
    assert board.log_tail()[-1].endswith("hello")
    assert board.stats()["requests"] == 0


def test_default_graph_matches_the_engine():
    board = ScanBoard()
    assert [phase_id for _, phase_id, _ in board.phases()] == \
        list(default_graph().ids())


# ------------------------------------------------------------ event sources

def test_read_events_returns_good_events_and_counts_the_corrupt_line(tmp_path):
    path = tmp_path / "events.jsonl"
    first = _event("run-started", seq=1, target="acme.test")
    last = _event("run-finished", seq=3, status="completed")
    truncated = '{"seq": 2, "ts": "2026-11-04T12:00:01.000+00:00"'  # crash cut it
    path.write_text(
        "\n".join([json.dumps(first), truncated, json.dumps(last), ""]),
        encoding="utf-8",
    )
    events, skipped = read_events(path)
    assert events == [first, last]
    assert skipped == 1


def test_replay_yields_the_recorded_events_and_skips_malformed_lines(tmp_path):
    path = tmp_path / "events.jsonl"
    first = _event("run-started", seq=1, target="acme.test")
    last = _event("run-finished", seq=2, status="completed")
    path.write_text(
        f"{json.dumps(first)}\nnot json at all\n{json.dumps(last)}\n",
        encoding="utf-8",
    )
    assert list(replay(path)) == [first, last]


def test_follow_yields_appended_events_then_stops_after_run_finished(tmp_path):
    path = tmp_path / "events.jsonl"
    path.write_text("", encoding="utf-8")
    stop = threading.Event()

    def writer():
        for delay, batch in [
            (0.05, [_event("run-started", seq=1, target="acme.test"),
                    _event("phase-started", "liveness", seq=2)]),
            (0.05, [_event("run-finished", seq=3, status="completed")]),
        ]:
            stop.wait(delay)  # let the follower settle into its poll loop
            with open(path, "a", encoding="utf-8") as fh:
                fh.writelines(json.dumps(event) + "\n" for event in batch)

    tailer = threading.Thread(target=writer)
    tailer.start()
    events = list(follow(path, stop, poll=0.01))
    tailer.join(timeout=5)
    assert [event["seq"] for event in events] == [1, 2, 3]
    assert events[-1]["type"] == "run-finished"


def test_follow_polls_for_a_missing_file_and_returns_once_stop_is_set(tmp_path):
    stop = threading.Event()
    stop.set()  # already asked to stop: no file, no events, no hang
    assert list(follow(tmp_path / "nope.jsonl", stop, poll=0.01)) == []


# -------------------------------------------------------------- shared art

def test_logo_is_multiline_ascii_within_width():
    from wpbuddy.tui.art import LOGO

    lines = LOGO.splitlines()
    assert len(lines) >= 5
    for line in lines:
        assert line.strip(), "logo must have at least 5 non-blank lines"
        assert line.isascii()
        assert len(line) <= 78


def test_cli_banner_pairs_logo_with_intro_and_disclaimer():
    from wpbuddy.tui.art import CLI_BANNER, LOGO

    assert LOGO in CLI_BANNER
    assert "WpBuddy - WordPress vulnerability scanner" in CLI_BANNER
    assert "An open-source vulnerability scanner for websites using WordPress." in CLI_BANNER
    assert "- this project is related to Website Security and must not be used\n" \
        "  for malicious activities." in CLI_BANNER
    assert "- never scan a website you do not own or are not authorized to test." in CLI_BANNER


def test_cli_reuses_the_shared_banner_object():
    import wpbuddy.cli as cli
    from wpbuddy.tui import art

    assert cli.BANNER is art.CLI_BANNER


# ------------------------------------------------------------ flow screen
#
# The Textual shell (`wpbuddy.tui.app`) is tested twice over: once through
# Textual's headless pilot (`asyncio.run` + `app.run_test()` — no real
# terminal, no pytest-asyncio), and once through fakes for `FlowApp` and
# `subprocess.Popen` so the live-scan mechanics (spawn, tail, interrupt)
# never start a real scan. Textual itself is only ever imported by
# `wpbuddy/tui/app.py`; these tests import it transitively, never directly.


def _write_events(path, events):
    """Write an events.jsonl exactly the way a recorded run leaves it."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(event) + "\n" for event in events),
                    encoding="utf-8")


class _FakeApp:
    """FlowApp double: drains the event source into the board, records itself."""

    instances = []

    def __init__(self, source=None, board=None, command="", **kwargs):
        self.source = source
        self.board = board
        self.command = command
        self.kwargs = kwargs
        _FakeApp.instances.append(self)

    def run(self):
        for event in self.source():
            self.board.apply(event)
        return 0


class _FakePopen:
    """Popen double: never spawns; can write the run log and/or stay 'running'."""

    spawns = []

    def __init__(self, cmd, events_path=None, events=None, running=False,
                 exit_code=0, **kwargs):
        self.cmd = list(cmd)
        self.kwargs = kwargs
        self.pid = 4242
        self.signals = []
        self.returncode = None if running else exit_code
        if events_path is not None:
            _write_events(events_path, events or _script())
        _FakePopen.spawns.append(self)

    def poll(self):
        return self.returncode

    def wait(self, timeout=None):
        return self.returncode if self.returncode is not None else -9

    def send_signal(self, sig):
        self.signals.append(sig)

    def terminate(self):
        self.signals.append(signal.SIGTERM)

    def kill(self):
        self.signals.append(signal.SIGKILL)
        self.returncode = -9


# ------------------------------------------------------ subcommand plumbing

def test_flow_subcommand_and_aliases_are_dispatched(tmp_path, monkeypatch):
    from wpbuddy import cli
    from wpbuddy.tui import app as flow

    assert {"flow", "tui", "explain"} <= set(cli.SUBCOMMANDS)
    monkeypatch.setattr(flow, "textual_available", lambda: False)
    monkeypatch.setattr(flow, "FlowApp",
                        lambda *a, **k: pytest.fail("no app may run in this test"))
    for name in ("flow", "tui", "explain"):
        with pytest.raises(SystemExit) as caught:
            cli.main([name, "--run", str(tmp_path / "missing.jsonl")])
        assert caught.value.code == 2


def test_textual_available_is_find_spec_based(monkeypatch):
    import importlib.util

    from wpbuddy.tui import app as flow

    assert flow.textual_available() == (importlib.util.find_spec("textual") is not None)
    monkeypatch.setattr(importlib.util, "find_spec", lambda name: None)
    assert flow.textual_available() is False


def test_textual_is_imported_only_by_the_tui_app_module():
    import wpbuddy

    root = Path(wpbuddy.__file__).parent

    def imports_textual(path):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import) and \
                    any(alias.name.split(".")[0] == "textual" for alias in node.names):
                return True
            if isinstance(node, ast.ImportFrom) and \
                    (node.module or "").split(".")[0] == "textual":
                return True
        return False

    offenders = [str(p.relative_to(root)) for p in root.rglob("*.py")
                 if p != root / "tui" / "app.py" and imports_textual(p)]
    assert offenders == []


# ------------------------------------------------------- source resolution

def test_run_flow_with_a_bad_run_path_exits_2(tmp_path, capsys, monkeypatch):
    from wpbuddy.tui import app as flow

    monkeypatch.setattr(flow, "FlowApp",
                        lambda *a, **k: pytest.fail("a bad --run must not launch the app"))
    assert flow.run_flow(["--run", str(tmp_path / "nope.jsonl")]) == 2
    assert "run log not found" in capsys.readouterr().out
    assert flow.run_flow(["--run", str(tmp_path)]) == 2  # directory without events.jsonl


def test_run_flow_replays_a_recorded_run_file_or_directory(tmp_path, monkeypatch):
    from wpbuddy.tui import app as flow

    run = tmp_path / "wpbuddy-audit" / "acme.test" / "runs" / "20261104-120000-abc"
    _write_events(run / "events.jsonl", _script())
    (run / "meta.json").write_text(json.dumps({"target": "https://acme.test/"}),
                                   encoding="utf-8")
    _FakeApp.instances.clear()
    monkeypatch.setattr(flow, "FlowApp", _FakeApp)

    assert flow.run_flow(["--run", str(run / "events.jsonl")]) == 0
    app = _FakeApp.instances[-1]
    assert app.command == f"wpbuddy flow --run {run / 'events.jsonl'}"
    assert app.kwargs["target"] == "acme.test"  # target read from the run's meta.json
    assert app.board.stats()["status"] == "completed"

    assert flow.run_flow(["--run", str(run)]) == 0  # a run directory resolves too
    assert _FakeApp.instances[-1].command.endswith("events.jsonl")


def test_run_flow_defaults_to_the_newest_recorded_run(tmp_path, monkeypatch):
    from wpbuddy.tui import app as flow

    monkeypatch.chdir(tmp_path)
    older = tmp_path / "wpbuddy-audit" / "old.test" / "runs" / "run-old"
    newer = tmp_path / "wpbuddy-audit" / "new.test" / "runs" / "run-new"
    _write_events(older / "events.jsonl", _script())
    _write_events(newer / "events.jsonl", _script())
    os.utime(older / "events.jsonl", (1, 1))
    os.utime(newer / "events.jsonl", (2, 2))
    _FakeApp.instances.clear()
    monkeypatch.setattr(flow, "FlowApp", _FakeApp)

    assert flow.run_flow([]) == 0
    command = _FakeApp.instances[-1].command
    assert "new.test" in command and "run-new" in command  # newest wins
    assert "old.test" not in command


def test_run_flow_with_no_target_and_no_runs_exits_2(tmp_path, monkeypatch, capsys):
    from wpbuddy.tui import app as flow

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(flow, "FlowApp",
                        lambda *a, **k: pytest.fail("nothing to show, nothing to run"))
    assert flow.run_flow([]) == 2
    assert "no recorded runs found - pass --target or --run" in capsys.readouterr().out


def test_run_flow_without_textual_hints_and_spawns_nothing(monkeypatch, tmp_path, capsys):
    from wpbuddy.tui import app as flow

    events = tmp_path / "events.jsonl"
    _write_events(events, _script())

    def no_app(*args, **kwargs):
        raise AssertionError("the app must not run without textual")

    def no_spawn(*args, **kwargs):
        raise AssertionError("no scan may be spawned without textual")

    monkeypatch.setattr(flow, "textual_available", lambda: False)
    monkeypatch.setattr(flow, "FlowApp", no_app)
    monkeypatch.setattr(flow.subprocess, "Popen", no_spawn)

    assert flow.run_flow(["--run", str(events)]) == 2
    assert "pip install 'wpbuddy[tui]'" in capsys.readouterr().out
    assert flow.run_flow(["--target", "https://acme.test/"]) == 2
    assert "pip install 'wpbuddy[tui]'" in capsys.readouterr().out


# ------------------------------------------------------ live-scan mechanics

def test_run_flow_spawns_the_scan_and_tails_the_new_run(tmp_path, monkeypatch):
    from wpbuddy.tui import app as flow

    monkeypatch.chdir(tmp_path)
    events = tmp_path / "wpbuddy-audit" / "acme.test" / "runs" / \
        "20261104-120000-abc" / "events.jsonl"

    def fake_popen(cmd, **kwargs):
        return _FakePopen(cmd, events_path=events, events=_script(), **kwargs)

    monkeypatch.setattr(flow.subprocess, "Popen", fake_popen)
    _FakeApp.instances.clear()
    _FakePopen.spawns.clear()
    monkeypatch.setattr(flow, "FlowApp", _FakeApp)

    assert flow.run_flow(["--target", "https://acme.test/", "--profile", "deep"]) == 0

    spawn = _FakePopen.spawns[0]
    assert spawn.cmd == [sys.executable, "-m", "wpbuddy.cli", "scan",
                         "--target", "https://acme.test/", "--profile", "deep"]
    assert spawn.kwargs.get("start_new_session") is True  # own process group
    app = _FakeApp.instances[-1]
    assert app.board.log_tail()  # tailed the new run's events.jsonl
    assert app.board.stats()["status"] == "completed"
    assert app.kwargs["profile"] == "deep"


def test_run_flow_sends_sigint_to_the_child_group_at_quit(tmp_path, monkeypatch):
    from wpbuddy.tui import app as flow

    monkeypatch.chdir(tmp_path)
    events = tmp_path / "wpbuddy-audit" / "acme.test" / "runs" / \
        "20261104-120000-abc" / "events.jsonl"
    sent = []

    def fake_popen(cmd, **kwargs):
        return _FakePopen(cmd, events_path=events, events=_script(),
                          running=True, **kwargs)

    monkeypatch.setattr(flow.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(flow.os, "killpg",
                        lambda pgid, sig: sent.append((pgid, sig)))
    monkeypatch.setattr(flow, "_INTERRUPT_GRACE", 0.05)
    _FakeApp.instances.clear()
    _FakePopen.spawns.clear()
    monkeypatch.setattr(flow, "FlowApp", _FakeApp)

    assert flow.run_flow(["--target", "https://acme.test/"]) == 0
    child = _FakePopen.spawns[-1]
    assert (child.pid, signal.SIGINT) in sent  # SIGINT goes to the process group
    assert sent[-1] == (child.pid, signal.SIGKILL)  # then SIGKILL once grace expires


# ---------------------------------------------------------- the app itself

async def _settle(app, seconds=5.0):
    """Wait (without blocking the loop) for the pump thread to finish feeding."""
    deadline = time.monotonic() + seconds
    while not app.source_done.is_set() and time.monotonic() < deadline:
        await asyncio.sleep(0.02)
    assert app.source_done.is_set(), "the event pump did not finish"
    await asyncio.sleep(0.02)  # let the last refresh land


def _item_texts(widget):
    """Rendered text of the child widgets inside one pane widget."""
    return [str(child.render()) for child in widget.children]


def test_flow_app_renders_a_recorded_run(tmp_path):
    from wpbuddy.tui.app import FlowApp

    events = tmp_path / "events.jsonl"
    _write_events(events, _script())
    app = FlowApp(source=lambda: replay(events), board=ScanBoard(),
                  command=f"wpbuddy flow --run {events}", target="acme.test")

    async def scenario():
        async with app.run_test() as pilot:
            await _settle(app)
            rail = app.query_one("#rail")
            rows = [text for item in rail.children for text in _item_texts(item)]
            assert any("✓" in row and "liveness" in row for row in rows), rows
            assert any("⊘" in row and "deep-discovery" in row for row in rows), rows
            detail = str(app.query_one("#detail").render())
            assert "verify the target answers" in detail  # selected phase's purpose
            topbar = str(app.query_one("#topbar").render())
            assert "acme.test" in topbar and "requests" in topbar
            assert app.log_lines_rendered == len(_script())
            assert app.query_one("#log").lines  # the log pane painted something

            before = len(rail.children)
            app.apply_event(_event("phase-started", "ghost-phase"))  # unknown phase
            await pilot.pause()
            assert len(app.query_one("#rail").children) == before  # ignored, no crash

    asyncio.run(scenario())


def test_flow_app_bindings_copy_about_and_quit(tmp_path):
    from wpbuddy.tui.app import FlowApp

    events = tmp_path / "events.jsonl"
    _write_events(events, _script())
    assert {"q", "c", "question_mark"} <= {binding.key for binding in FlowApp.BINDINGS}

    app = FlowApp(source=lambda: replay(events), board=ScanBoard(),
                  command=f"wpbuddy flow --run {events}", target="acme.test")
    copied = []

    async def scenario():
        async with app.run_test() as pilot:
            await _settle(app)
            app.copy_to_clipboard = copied.append  # shim over the App method
            about = app.query_one("#about")
            assert about.display is False
            await pilot.press("question_mark")
            await pilot.pause()
            assert about.display is True
            assert "single-screen" in str(about.render())  # about pane describes the app
            await pilot.press("c")
            await pilot.pause()
            assert copied == [app.command]  # copies the spawn command
            await pilot.press("q")
            for _ in range(100):  # quit must actually stop the app
                if not app.is_running:
                    break
                await asyncio.sleep(0.02)
            assert not app.is_running

    asyncio.run(scenario())


def test_flow_app_arrow_keys_move_the_phase_detail(tmp_path):
    from wpbuddy.tui.app import FlowApp

    events = tmp_path / "events.jsonl"
    _write_events(events, _script())
    app = FlowApp(source=lambda: replay(events), board=ScanBoard(),
                  command=f"wpbuddy flow --run {events}", target="acme.test")

    async def scenario():
        async with app.run_test() as pilot:
            await _settle(app)
            rail = app.query_one("#rail")
            assert rail.has_focus  # the rail is focused on mount: ↑↓ just work
            assert rail.index == 0  # liveness
            assert "verify the target answers" in str(app.query_one("#detail").render())
            await pilot.press("down")  # arrows highlight; the detail must follow
            await pilot.pause()
            assert rail.index == 1
            assert "GET-only recon" in str(app.query_one("#detail").render())
            await pilot.press("up")
            await pilot.pause()
            assert rail.index == 0
            assert "verify the target answers" in str(app.query_one("#detail").render())

    asyncio.run(scenario())


def test_flow_app_reports_a_broken_source_in_the_log_pane(tmp_path):
    from wpbuddy.tui.app import FlowApp

    events = tmp_path / "events.jsonl"
    _write_events(events, _script())

    def source():
        yield from replay(events)
        raise RuntimeError("the run log vanished")  # a frozen, broken feed

    app = FlowApp(source=source, board=ScanBoard(), command="wpbuddy", target="acme.test")

    async def scenario():
        async with app.run_test():
            await _settle(app)
            assert app.board.stats()["status"] == "completed"  # earlier events landed
            last = app.query_one("#log").lines[-1].text
            assert "event source failed: the run log vanished" in last

    asyncio.run(scenario())


def test_flow_app_log_pane_caps_its_window_without_dropping_new_lines(tmp_path, monkeypatch):
    from wpbuddy.tui import app as flow

    events = tmp_path / "events.jsonl"
    _write_events(events, _script())  # 10 events, window smaller than that
    monkeypatch.setattr(flow, "_LOG_WINDOW", 5)
    app = flow.FlowApp(source=lambda: replay(events), board=ScanBoard(),
                       command="wpbuddy", target="acme.test")

    async def scenario():
        async with app.run_test() as pilot:
            await _settle(app)
            assert app.query_one("#log").max_lines == 5  # the pane bounds retention
            assert app.log_lines_rendered == len(_script())  # everything rendered
            for i in range(3):  # past the window, new events must still land
                app.apply_event(_event("http-response", "passive", seq=100 + i,
                                       url=f"http://acme.test/x{i}", status=200))
            await pilot.pause()
            assert app.log_lines_rendered == len(_script()) + 3
            assert "x2" in app.query_one("#log").lines[-1].text  # the newest line

    asyncio.run(scenario())


def test_run_flow_with_run_and_target_replays_without_spawning(tmp_path, monkeypatch):
    from wpbuddy.tui import app as flow

    run = tmp_path / "wpbuddy-audit" / "acme.test" / "runs" / "20261104-120000-abc"
    _write_events(run / "events.jsonl", _script())

    def no_spawn(*args, **kwargs):
        raise AssertionError("--run must win: no scan may be spawned")

    monkeypatch.setattr(flow.subprocess, "Popen", no_spawn)
    _FakeApp.instances.clear()
    monkeypatch.setattr(flow, "FlowApp", _FakeApp)

    assert flow.run_flow(["--run", str(run / "events.jsonl"),
                          "--target", "https://other.test/"]) == 0
    app = _FakeApp.instances[-1]
    assert app.board.stats()["status"] == "completed"  # replayed the recorded run
    assert str(run) in app.command  # ...not a spawn of the other target
    assert app.kwargs["target"] == "acme.test"  # recorded run's host, not --target's


def test_spawn_and_locate_tolerates_a_missing_host(tmp_path, monkeypatch):
    from wpbuddy.tui import app as flow

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(flow.subprocess, "Popen", lambda cmd, **kw: _FakePopen(cmd, **kw))
    _FakePopen.spawns.clear()
    events_path, proc = flow._spawn_and_locate(["echo"], None)
    assert events_path is None  # defensive: a None host must not raise
    assert proc.poll() == 0


# ------------------------------------------------- runs-root discovery

def test_run_flow_finds_runs_under_the_stable_runs_root(tmp_path, monkeypatch):
    from wpbuddy import config
    from wpbuddy.tui import app as flow

    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()  # CWD: no wpbuddy-audit anywhere
    monkeypatch.chdir(elsewhere)
    runs = tmp_path / "runs-root"
    monkeypatch.setattr(config, "RUNS_DIR", runs)
    run = runs / "acme.test" / "runs" / "20261104-120000-abc"
    _write_events(run / "events.jsonl", _script())
    _FakeApp.instances.clear()
    monkeypatch.setattr(flow, "FlowApp", _FakeApp)

    assert flow.runs_root() == runs  # honors config.RUNS_DIR like the store
    assert flow.run_flow([]) == 0
    app = _FakeApp.instances[-1]
    assert "acme.test" in app.command  # found under the root, CWD irrelevant
    assert app.board.stats()["status"] == "completed"


def test_run_flow_prefers_the_runs_root_over_legacy_cwd_runs(tmp_path, monkeypatch):
    from wpbuddy import config
    from wpbuddy.tui import app as flow

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(config, "RUNS_DIR", tmp_path / "runs-root")
    root_run = tmp_path / "runs-root" / "new.test" / "runs" / "run-new"
    legacy_run = tmp_path / "wpbuddy-audit" / "old.test" / "runs" / "run-old"
    _write_events(root_run / "events.jsonl", _script())
    _write_events(legacy_run / "events.jsonl", _script())
    os.utime(root_run / "events.jsonl", (3, 3))
    os.utime(legacy_run / "events.jsonl", (2, 2))
    _FakeApp.instances.clear()
    monkeypatch.setattr(flow, "FlowApp", _FakeApp)

    assert flow.run_flow([]) == 0
    command = _FakeApp.instances[-1].command
    assert "new.test" in command  # the runs root is searched first
    assert "old.test" not in command


def test_run_flow_falls_back_to_legacy_cwd_runs_when_root_empty(tmp_path, monkeypatch):
    from wpbuddy import config
    from wpbuddy.tui import app as flow

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(config, "RUNS_DIR", tmp_path / "empty-root")
    (tmp_path / "empty-root").mkdir(exist_ok=True)  # root present, no runs yet
    legacy = tmp_path / "wpbuddy-audit" / "old.test" / "runs" / "20260101-000000-aaa"
    _write_events(legacy / "events.jsonl", _script())
    _FakeApp.instances.clear()
    monkeypatch.setattr(flow, "FlowApp", _FakeApp)

    assert flow.run_flow([]) == 0  # pre-feature runs still open
    assert "old.test" in _FakeApp.instances[-1].command


def test_run_flow_spawns_and_tails_under_the_runs_root(tmp_path, monkeypatch):
    from wpbuddy import config
    from wpbuddy.tui import app as flow

    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    monkeypatch.chdir(elsewhere)
    runs = tmp_path / "runs-root"
    monkeypatch.setattr(config, "RUNS_DIR", runs)
    events = runs / "acme.test" / "runs" / "20261104-120000-abc" / "events.jsonl"

    def fake_popen(cmd, **kwargs):
        return _FakePopen(cmd, events_path=events, events=_script(), **kwargs)

    monkeypatch.setattr(flow.subprocess, "Popen", fake_popen)
    _FakeApp.instances.clear()
    _FakePopen.spawns.clear()
    monkeypatch.setattr(flow, "FlowApp", _FakeApp)

    assert flow.run_flow(["--target", "https://acme.test/"]) == 0
    app = _FakeApp.instances[-1]
    assert app.board.stats()["status"] == "completed"  # tailed the run under the root


def test_run_flow_watches_the_passthrough_runs_dir_for_a_live_scan(tmp_path, monkeypatch):
    from wpbuddy import config
    from wpbuddy.tui import app as flow

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(config, "RUNS_DIR", tmp_path / "default-root")
    custom = tmp_path / "custom-root"
    events = custom / "acme.test" / "runs" / "20261104-120000-abc" / "events.jsonl"

    def fake_popen(cmd, **kwargs):
        assert "--runs-dir" in cmd  # forwarded to the scan subprocess verbatim
        return _FakePopen(cmd, events_path=events, events=_script(), **kwargs)

    monkeypatch.setattr(flow.subprocess, "Popen", fake_popen)
    _FakeApp.instances.clear()
    _FakePopen.spawns.clear()
    monkeypatch.setattr(flow, "FlowApp", _FakeApp)

    assert flow.run_flow(["--target", "https://acme.test/",
                          "--runs-dir", str(custom)]) == 0
    # the watcher followed the child's --runs-dir, not config.RUNS_DIR
    assert _FakeApp.instances[-1].board.stats()["status"] == "completed"


def test_run_flow_expands_tilde_in_passthrough_runs_dir(tmp_path, monkeypatch):
    from wpbuddy import config
    from wpbuddy.tui import app as flow

    home = tmp_path / "home"
    (home / "my-runs").mkdir(parents=True)
    monkeypatch.setenv("HOME", str(home))  # expanduser() reads HOME at call time
    cwd = tmp_path / "cwd"
    cwd.mkdir()  # no literal './~/my-runs' here: only the expansion can match
    monkeypatch.chdir(cwd)
    monkeypatch.setattr(config, "RUNS_DIR", tmp_path / "default-root")
    events = home / "my-runs" / "acme.test" / "runs" / "20261104-120000-abc" / "events.jsonl"

    def fake_popen(cmd, **kwargs):
        assert "~/my-runs" in cmd  # the child gets it verbatim, expands its own
        return _FakePopen(cmd, events_path=events, events=_script(), **kwargs)

    monkeypatch.setattr(flow.subprocess, "Popen", fake_popen)
    _FakeApp.instances.clear()
    _FakePopen.spawns.clear()
    monkeypatch.setattr(flow, "FlowApp", _FakeApp)

    assert flow.run_flow(["--target", "https://acme.test/",
                          "--runs-dir", "~/my-runs"]) == 0
    # the watcher expanded ~ exactly like the spawned scan will
    assert _FakeApp.instances[-1].board.stats()["status"] == "completed"


# --------------------------------------------------------- final fix wave

class _CrashingApp(_FakeApp):
    """FlowApp double whose run() dies the way an abnormal TUI death would."""

    def run(self):
        raise RuntimeError("textual died mid-run")


def test_check_events_summarize_their_subphase():
    board = ScanBoard()
    board.apply(_event("check-started", "report", subphase="write"))
    board.apply(_event("check-finished", "report", subphase="write"))
    started, done = board.log_tail()
    assert "write" in started and "started" in started
    assert "write" in done and "done" in done


def test_run_flow_stops_the_child_when_the_app_dies(tmp_path, monkeypatch):
    from wpbuddy.tui import app as flow

    monkeypatch.chdir(tmp_path)
    events = tmp_path / "wpbuddy-audit" / "acme.test" / "runs" / \
        "20261104-120000-abc" / "events.jsonl"
    sent = []

    def fake_popen(cmd, **kwargs):
        return _FakePopen(cmd, events_path=events, events=_script(),
                          running=True, **kwargs)

    monkeypatch.setattr(flow.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(flow.os, "killpg", lambda pgid, sig: sent.append((pgid, sig)))
    monkeypatch.setattr(flow, "_INTERRUPT_GRACE", 0.05)
    _FakePopen.spawns.clear()
    monkeypatch.setattr(flow, "FlowApp", _CrashingApp)

    with pytest.raises(RuntimeError, match="textual died mid-run"):
        flow.run_flow(["--target", "https://acme.test/"])
    child = _FakePopen.spawns[-1]
    assert (child.pid, signal.SIGINT) in sent  # the orphaned scan was stopped
    assert (child.pid, signal.SIGKILL) in sent


def test_child_guard_signal_handler_stops_the_child(tmp_path, monkeypatch):
    from wpbuddy.tui import app as flow

    sent = []
    monkeypatch.setattr(flow.os, "killpg", lambda pgid, sig: sent.append((pgid, sig)))
    monkeypatch.setattr(flow, "_INTERRUPT_GRACE", 0.05)
    child = _FakePopen(["wpbuddy scan"], running=True)
    guard = flow._ChildGuard(child).install()
    try:
        with pytest.raises(SystemExit) as caught:
            guard._handle(signal.SIGTERM, None)  # a closed terminal, effectively
    finally:
        guard.close()
    assert (child.pid, signal.SIGINT) in sent
    assert caught.value.code == 128 + signal.SIGTERM  # conventional death code


def test_flow_app_copy_notification_tolerates_markup_characters(tmp_path):
    from wpbuddy.tui.app import FlowApp

    events = tmp_path / "events.jsonl"
    _write_events(events, _script())
    app = FlowApp(source=lambda: replay(events), board=ScanBoard(),
                  command="wpbuddy flow --run [a-z].jsonl", target="acme.test")
    copied = []

    async def scenario():
        async with app.run_test() as pilot:
            await _settle(app)
            app.copy_to_clipboard = copied.append
            await pilot.press("c")  # the command's brackets must not parse as markup
            await pilot.pause()
            assert copied == [app.command]
            assert app.is_running

    asyncio.run(scenario())


def test_run_flow_reads_the_profile_from_a_recorded_runs_meta(tmp_path, monkeypatch):
    from wpbuddy.tui import app as flow

    run = tmp_path / "wpbuddy-audit" / "acme.test" / "runs" / "20261104-120000-abc"
    _write_events(run / "events.jsonl", _script())
    (run / "meta.json").write_text(json.dumps({
        "target": "https://acme.test/",
        "argv": ["--target", "https://acme.test/", "--profile", "deep"],
    }), encoding="utf-8")
    _FakeApp.instances.clear()
    monkeypatch.setattr(flow, "FlowApp", _FakeApp)

    assert flow.run_flow(["--run", str(run)]) == 0
    assert _FakeApp.instances[-1].kwargs["profile"] == "deep"  # from meta.json argv


def test_run_flow_clamps_signal_death_exit_codes(tmp_path, monkeypatch):
    from wpbuddy.tui import app as flow

    monkeypatch.chdir(tmp_path)
    events = tmp_path / "wpbuddy-audit" / "acme.test" / "runs" / \
        "20261104-120000-abc" / "events.jsonl"

    def fake_popen(cmd, **kwargs):
        return _FakePopen(cmd, events_path=events, events=_script(),
                          exit_code=-15, **kwargs)  # scan killed by a signal

    monkeypatch.setattr(flow.subprocess, "Popen", fake_popen)
    _FakeApp.instances.clear()
    monkeypatch.setattr(flow, "FlowApp", _FakeApp)

    assert flow.run_flow(["--target", "https://acme.test/"]) == 0  # not -15


def test_flow_app_http_response_does_not_rebuild_the_rail(tmp_path):
    from wpbuddy.tui.app import FlowApp

    events = tmp_path / "events.jsonl"
    _write_events(events, _script())
    app = FlowApp(source=lambda: replay(events), board=ScanBoard(),
                  command=f"wpbuddy flow --run {events}", target="acme.test")

    async def scenario():
        async with app.run_test() as pilot:
            await _settle(app)
            rail = app.query_one("#rail")
            before = [id(child) for child in rail.children]
            app.apply_event(_event("http-response", "passive",
                                   url="http://acme.test/late", status=200))
            await pilot.pause()
            after = [id(child) for child in rail.children]
            assert after == before  # same ListItem objects: the rail was not rebuilt
            assert "late" in app.query_one("#log").lines[-1].text  # log DID append
            assert "requests 3" in str(app.query_one("#topbar").render())  # top bar too
            app.apply_event(_event("phase-started", "active"))
            await pilot.pause()
            assert [id(child) for child in rail.children] != before  # phases rebuild it

    asyncio.run(scenario())
