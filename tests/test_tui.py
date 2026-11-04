"""Unit tests for the TUI's pure event board (`wpbuddy.tui.render`).

The board folds event dicts shaped like `Event.to_dict()` (see
`wpbuddy.engine.events`) into pane models: phase-rail glyphs, phase detail
text, findings, a formatted log tail and top-bar stats. It is pure stdlib —
no Textual, no I/O — so the app pane code only renders what these methods
return.
"""

from wpbuddy.engine.phases import PhaseSpec, default_graph
from wpbuddy.tui.render import ScanBoard

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
