"""Engine scaffolding: phase graph, event bus and run log.

These tests cover the shared foundation the TUI will observe: the graph is
documented and has a handler, preconditions are skips with reasons, the bus
isolates broken subscribers, and a run can be recorded/replayed.
"""

import json
from types import SimpleNamespace

import pytest
from mockwp_server import start_mock_wp

from wpbuddy import cli, confidence, httpclient
from wpbuddy.engine import events as scan_events
from wpbuddy.engine.events import Event, EventBus, EventType
from wpbuddy.engine.phases import PhaseGraph, PhaseSpec, Precondition, default_graph
from wpbuddy.engine.run import HANDLERS, ScanContext, ScanEngine
from wpbuddy.report import Report
from wpbuddy.runs.store import RunStore, iter_events


@pytest.fixture(autouse=True)
def _offline_db(monkeypatch):
    """Keep the vulnerability API out of engine tests (fast, deterministic)."""
    from wpbuddy import vulndb
    monkeypatch.setattr(vulndb, "_fetch", lambda kind, slug: None)


@pytest.fixture(scope="module")
def mock():
    server, base = start_mock_wp(0)
    yield base
    server.shutdown()


def _context(tmp_path, **overrides):
    args = SimpleNamespace(stealth=False, access=False, user=None, audit_code="source",
                           offline=True, persona=None, fail_on="none")
    for key, value in overrides.pop("args", {}).items():
        setattr(args, key, value)
    ctx = ScanContext(target=overrides.pop("target", "https://x.example.com/"),
                      args=args, report=Report(), model=confidence.ScanModel(),
                      bus=EventBus(), **overrides)
    return ctx


# ------------------------------------------------------------------ graph

def test_graph_is_documented_and_dispatchable():
    graph = default_graph()
    assert [p.id for p in graph.run_stage()] == [
        "liveness", "passive", "deep-discovery", "active", "access", "code-audit"]
    assert [p.id for p in graph.finalize_stage()] == [
        "waf-analysis", "error-analysis", "report"]
    for phase in graph:
        assert phase.purpose, phase.id
        assert phase.handler in HANDLERS, phase.id
        assert phase.inputs, phase.id
        assert phase.outputs, phase.id
        for sub in phase.subphases:
            assert sub.purpose, (phase.id, sub.id)


def test_graph_rejects_duplicates_and_unknown_stages():
    phase = PhaseSpec("a", "A", "p", "liveness")
    with pytest.raises(ValueError):
        PhaseGraph([phase, phase])
    with pytest.raises(ValueError):
        PhaseGraph([PhaseSpec("b", "B", "p", "liveness", stage="nope")])


def test_plan_marks_argument_skips_with_reasons():
    ctx = _context(None, args={"stealth": True, "access": False, "user": None})
    lines = {phase.id: (marker, note) for phase, marker, note in
             ScanEngine(ctx).plan_lines()}
    assert lines["active"][0] == "⊘"
    assert "--stealth" in lines["active"][1]
    assert lines["access"][0] == "⊘"
    assert "--access" in lines["access"][1]
    assert lines["code-audit"][0] == "✓"


def test_plan_marks_audit_off():
    ctx = _context(None, args={"audit_code": "off"})
    lines = {phase.id: (marker, note) for phase, marker, note in
             ScanEngine(ctx).plan_lines()}
    assert lines["code-audit"][0] == "⊘"
    assert "--audit-code off" in lines["code-audit"][1]


# -------------------------------------------------------------------- bus

def test_bus_isolates_broken_subscribers():
    bus = EventBus()
    received = []

    def broken(_event):
        raise RuntimeError("view crashed")

    bus.subscribe(broken)
    bus.subscribe(received.append)
    bus.emit(Event(EventType.PHASE_STARTED, "passive", {"purpose": "x"}))

    assert len(received) == 1
    assert bus.errors and "view crashed" in bus.errors[0]
    assert received[0].seq == 1


def test_bus_emitter_binds_phase_and_unsubscribe_works():
    bus = EventBus()
    seen = []
    unsubscribe = bus.subscribe(seen.append)
    bus.emitter("passive")(EventType.CHECK_STARTED, subphase="crawl")
    unsubscribe()
    bus.emitter("passive")(EventType.CHECK_FINISHED, subphase="crawl")

    assert len(seen) == 1
    assert seen[0].phase == "passive"
    assert seen[0].data["subphase"] == "crawl"


def test_engine_skips_without_calling_handler():
    ctx = _context(None)
    graph = PhaseGraph([PhaseSpec(
        "x", "X", "purpose", "liveness",
        preconditions=(Precondition("no", "never", lambda _ctx: False, "flag off"),))])
    engine = ScanEngine(ctx, graph=graph)
    engine.run()
    assert ctx.statuses["x"] == "skipped"
    skipped = [e for e in ctx.bus.history() if e.type == EventType.PHASE_SKIPPED]
    assert skipped and skipped[0].data["reasons"] == ["flag off"]


def test_finalize_clears_sink_even_for_empty_graph():
    ctx = _context(None)
    scan_events.set_sink(ctx.bus)
    engine = ScanEngine(ctx, graph=PhaseGraph([]))
    engine.finalize("ok")
    assert scan_events.sink() is None


# ---------------------------------------------------------------- run log

def test_run_store_appends_meta_and_replays(tmp_path):
    store = RunStore("example.com", base=tmp_path)
    run_id = store.create("https://example.com/", argv=["--target", "x"])
    assert run_id and store.dir.is_dir()

    bus = EventBus()
    unsubscribe = store.attach(bus)
    bus.emit(Event(EventType.PHASE_STARTED, "passive", {"purpose": "recon"}))
    bus.emit(Event(EventType.PHASE_SKIPPED, "active", {"reasons": ["--stealth"]}))
    unsubscribe()
    store.finish({"status": "ok"})

    meta = json.loads((store.dir / "meta.json").read_text())
    assert meta["target"] == "https://example.com/"
    assert meta["status"] == "ok"
    assert meta["finished_at"]

    replayed = list(iter_events("example.com", run_id, base=tmp_path))
    assert [e.type for e in replayed] == [EventType.PHASE_STARTED, EventType.PHASE_SKIPPED]
    assert [e.seq for e in replayed] == [1, 2]
    assert replayed[0].data["purpose"] == "recon"


def test_run_store_survives_unwritable_base(tmp_path):
    blocker = tmp_path / "not-a-dir"
    blocker.write_text("x")
    store = RunStore("example.com", base=blocker)
    assert store.create("https://example.com/") is None
    store.append(Event(EventType.RUN_STARTED))  # must be a no-op
    assert list(store.events()) == []


# ------------------------------------------------------------------- CLI

def test_cli_plan_sends_no_requests(capsys, monkeypatch):
    def fail(*_args, **_kwargs):
        raise AssertionError("--plan must not send a request")

    monkeypatch.setattr(httpclient, "request", fail)
    with pytest.raises(SystemExit) as exc:
        cli.main(["--target", "https://x.example.com/", "--plan", "--stealth"])
    assert exc.value.code == 0
    out = capsys.readouterr().out
    assert "Run stage" in out and "Finalize stage" in out
    assert "⊘ active" in out and "--stealth" in out


def test_cli_explain_writes_annotations_and_run_log(mock, tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    with pytest.raises(SystemExit) as exc:
        cli.main(["--target", mock, "--pluginList", "", "--audit-code", "off",
                  "--explain", "--output", str(tmp_path / "report")])
    assert exc.value.code == 0
    out = capsys.readouterr().out
    assert "[run]  passive" in out
    assert "[check] passive crawl" in out

    runs = list((tmp_path / "wpbuddy-audit").rglob("events.jsonl"))
    assert len(runs) == 1
    types = [json.loads(line)["type"] for line in runs[0].read_text().splitlines()]
    assert "run-started" in types and "run-finished" in types
    meta = json.loads((runs[0].parent / "meta.json").read_text())
    assert meta["status"] == "ok"


def test_cli_unreachable_target_still_writes_partial_report(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    with pytest.raises(SystemExit) as exc:
        cli.main(["--target", "http://127.0.0.1:1/", "--audit-code", "off",
                  "--output", str(tmp_path / "report")])
    assert exc.value.code == 1
    assert "could not be reached" in (tmp_path / "report.md").read_text()
    meta = json.loads(next((tmp_path / "wpbuddy-audit").rglob("meta.json")).read_text())
    assert meta["status"] == "unreachable"


def test_cli_unwritable_report_exits_nonzero(mock, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    blocked = tmp_path / "report.md"
    blocked.mkdir()
    with pytest.raises(SystemExit) as exc:
        cli.main(["--target", mock, "--pluginList", "", "--audit-code", "off",
                  "--output", str(tmp_path / "report")])
    assert exc.value.code == 1


def test_cli_no_run_log(mock, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    with pytest.raises(SystemExit) as exc:
        cli.main(["--target", mock, "--pluginList", "", "--audit-code", "off",
                  "--no-run-log", "--output", str(tmp_path / "report")])
    assert exc.value.code == 0
    assert not list(tmp_path.rglob("events.jsonl"))


def test_cli_crashed_phase_still_writes_partial_report_and_event(mock, tmp_path, monkeypatch):
    from wpbuddy import passive

    def boom(*_args, **_kwargs):
        raise RuntimeError("recon exploded")

    monkeypatch.setattr(passive, "run", boom)
    monkeypatch.chdir(tmp_path)
    with pytest.raises(SystemExit) as exc:
        cli.main(["--target", mock, "--pluginList", "", "--audit-code", "off",
                  "--output", str(tmp_path / "report")])
    assert exc.value.code == 1

    report = (tmp_path / "report.md").read_text()
    assert "recon exploded" in report
    events = next((tmp_path / "wpbuddy-audit").rglob("events.jsonl")).read_text()
    assert "phase-failed" in events
    meta = json.loads(next((tmp_path / "wpbuddy-audit").rglob("meta.json")).read_text())
    assert meta["status"] == "error"
