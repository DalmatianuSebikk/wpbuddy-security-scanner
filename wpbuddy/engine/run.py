"""The scan engine: walks `PhaseGraph`, emits events, finalizes the report.

There is exactly one orchestration path. The CLI drives this engine; the
future TUI will drive the same object and only observe. Handlers call the
existing phase modules, so the refactor adds a spine without forking the
scan.

Crash contract (unchanged from the old CLI): a failure in a run phase writes
a partial report, a phase failure is recorded as `phase-failed` with the
traceback message, and finalize still runs from `finally`.
"""

from __future__ import annotations

import sys
import time
import traceback
from dataclasses import dataclass, field
from pathlib import Path

from .. import __version__
from . import events as scan_events
from .events import Event, EventBus, EventType
from .phases import default_graph
from .reporting import (
    fail_on_check,
    write_diff_section,
    write_exec_summary,
    write_priorities,
)


class TargetUnreachable(Exception):
    """The liveness probe could not reach the target at all."""


@dataclass
class ScanContext:
    """Everything a phase may read or update during one run."""

    target: str
    args: object
    report: object
    model: object
    bus: EventBus
    run_id: str | None = None
    dict_list: list | None = None
    suppressions: list = field(default_factory=list)
    output: str = "outputScan"
    json_output: bool = False
    diff: str | None = None
    alive: bool = False
    completed: set = field(default_factory=set)
    statuses: dict = field(default_factory=dict)
    passive_results: dict = field(default_factory=dict)
    audited: dict = field(default_factory=dict)
    users: list = field(default_factory=list)
    xmlrpc_alive: bool = False
    fail_reason: str | None = None
    write_failed: bool = False
    started: float = field(default_factory=time.monotonic)
    # Engagement (roadmap 2.3): scope/authorization/budgets; persisted with
    # the run when a run store is attached.
    engagement: object | None = None
    # Run directory (set by the engine when a run store creates it); the
    # evidence layer (2.5) writes artifacts here.
    run_dir: object | None = None


# --------------------------------------------------------------------------
# Handlers. Each takes (ctx, emit) where emit is bound to the phase id.
# --------------------------------------------------------------------------

def _h_liveness(ctx, emit):
    from .. import httpclient
    resp = httpclient.get(ctx.target, retries=1)
    if resp is None:
        raise TargetUnreachable()
    ctx.alive = True


def _h_passive(ctx, emit):
    from .. import passive
    ctx.passive_results = passive.run(ctx.report, ctx.target, ctx.args,
                                      model=ctx.model, emit=emit)
    if getattr(ctx.args, "stealth", False):
        # The active phase is skipped in stealth mode; keep its closing rule.
        ctx.report.rule()


def _h_active(ctx, emit):
    from .. import active
    result = active.run(ctx.report, ctx.target, ctx.args, dict_list=ctx.dict_list,
                        model=ctx.model, include_access=False, emit=emit) or {}
    ctx.users = result.get("users", [])
    ctx.xmlrpc_alive = bool(result.get("xmlrpc_alive"))


def _h_access(ctx, emit):
    from ..active import access
    access.run_access(ctx.report, ctx.target, ctx.args, ctx.users, ctx.xmlrpc_alive,
                      dict_list=ctx.dict_list, model=ctx.model)


def _h_code_audit(ctx, emit):
    from .. import codeaudit
    ctx.audited = codeaudit.run(ctx.report, ctx.target, ctx.passive_results,
                                ctx.args, emit=emit)


def _h_waf_analysis(ctx, emit):
    from .. import waf
    waf.write_report(ctx.report)


def _h_error_analysis(ctx, emit):
    from ..passive import errorpages
    errorpages.write_report(ctx.report,
                            known_plugins=set(ctx.passive_results.get("plugins", {})))


def _h_report(ctx, emit):
    _section(emit, "priorities", lambda: write_priorities(ctx.report, ctx.model,
                                                          ctx.suppressions),
             "Risk summary skipped")
    if ctx.diff:
        _section(emit, "diff", lambda: write_diff_section(ctx.report, ctx.model,
                                                          ctx.diff, ctx.target),
                 "Diff section skipped")
    duration = time.monotonic() - ctx.started
    metadata = [
        ("Target", ctx.target),
        ("WpBuddy", __version__),
        ("Scanned", time.strftime("%Y-%m-%d %H:%M:%S")),
        ("Duration", f"{duration:.1f}s"),
        ("Profile", ("stealth " if getattr(ctx.args, "stealth", False) else "")
                    + (f"audit={getattr(ctx.args, 'audit_code', 'off')} ")
                    + ("offline " if getattr(ctx.args, "offline", False) else "")
                    + (f"persona={getattr(ctx.args, 'persona', None)}"
                       if getattr(ctx.args, "persona", None) else "persona=auto")),
    ]
    _section(emit, "summary", lambda: write_exec_summary(ctx.report, ctx.model, metadata),
             "Executive summary skipped")
    try:
        ctx.fail_reason = fail_on_check(ctx.model, getattr(ctx.args, "fail_on", "none"),
                                        ctx.suppressions)
    except Exception as exc:
        print(f"[*] --fail-on check skipped: {exc}")

    emit(EventType.CHECK_STARTED, subphase="write")
    report_path = f"{ctx.output}.md"
    try:
        ctx.report.write(report_path)
        print(f"[*] Report saved: {report_path}")
    except Exception as exc:
        ctx.write_failed = True
        print(f"[!] Could not write the report: {exc}")
        emit(EventType.ERROR, subphase="write", message=str(exc))
    if ctx.json_output:
        try:
            ctx.model.write_json(f"{ctx.output}.json", ctx.target)
            print(f"[*] Knowledge graph saved: {ctx.output}.json")
        except Exception as exc:
            print(f"[!] Could not write the JSON graph: {exc}")
    # Evidence layer (roadmap 2.5): the run's outputs are registered as
    # artifacts of the run, next to meta/engagement/events - one
    # self-describing directory per run.
    try:
        if ctx.run_dir is not None:
            from ..evidence import EvidenceStore
            store = EvidenceStore(ctx.run_dir, emit=emit)
            if not ctx.write_failed:
                store.register_artifact(report_path, "scan report (Markdown)")
            if ctx.json_output and Path(f"{ctx.output}.json").is_file():
                store.register_artifact(f"{ctx.output}.json", "knowledge graph (JSON)")
    except Exception as exc:  # bookkeeping must never fail the report phase
        print(f"[*] Artifact registration skipped: {exc}")
    emit(EventType.CHECK_FINISHED, subphase="write")


def _section(emit, name, action, skip_message):
    """Run one finalize section, recording and isolating broken sections."""
    emit(EventType.CHECK_STARTED, subphase=name)
    try:
        action()
    except Exception as exc:
        print(f"[*] {skip_message}: {exc}")
        emit(EventType.ERROR, subphase=name, message=f"{type(exc).__name__}: {exc}")
    emit(EventType.CHECK_FINISHED, subphase=name)


HANDLERS = {
    "liveness": _h_liveness,
    "passive": _h_passive,
    "active": _h_active,
    "access": _h_access,
    "code-audit": _h_code_audit,
    "waf-analysis": _h_waf_analysis,
    "error-analysis": _h_error_analysis,
    "report": _h_report,
}


class ExplainPrinter:
    """Plain-stdout `--explain`: the textual form of the TUI annotations."""

    PREFIX = {
        EventType.PHASE_STARTED: "[run]  ",
        EventType.PHASE_SKIPPED: "[skip] ",
        EventType.PHASE_FAILED: "[fail] ",
        EventType.CHECK_STARTED: "[check] ",
        EventType.CHECK_FINISHED: "[done] ",
        EventType.WAF_BYPASS: "[waf]  ",
        EventType.WAF_BLOCK: "[waf]  ",
        EventType.WAF_DETECTED: "[waf]  ",
        EventType.CONFIDENCE: "[conf] ",
        EventType.ERROR_PAGE: "[error] ",
        EventType.FINDING: "[find] ",
    }

    def __init__(self, stream=None):
        self.stream = stream or sys.stdout

    def __call__(self, event):
        prefix = self.PREFIX.get(event.type)
        if prefix is None:
            return
        subject = event.phase or ""
        details = event.data
        if event.type == EventType.PHASE_STARTED:
            text = details.get("purpose", "")
        elif event.type == EventType.PHASE_SKIPPED:
            text = "; ".join(details.get("reasons") or ()) or "skipped"
        elif event.type == EventType.PHASE_FAILED:
            text = details.get("message", "")
        elif event.type == EventType.CONFIDENCE:
            text = (f"{details.get('component')} score={details.get('score')} "
                    f"{details.get('tier')}")
        elif event.type == EventType.FINDING:
            text = (f"{details.get('component')} {details.get('detail') or details.get('name')}"
                    f" ({details.get('severity') or 'unrated'}"
                    f"{', ' + details['basis'] if details.get('basis') else ''})")
        elif event.type == EventType.WAF_DETECTED:
            text = f"{details.get('name')} via {details.get('via')}"
        elif event.type == EventType.WAF_BYPASS:
            subject = details.get("technique") or subject
            text = details.get("detail") or "bypass"
        elif event.type == EventType.WAF_BLOCK:
            text = "probe blocked"
        elif event.type == EventType.ERROR_PAGE:
            text = f"HTTP {details.get('status')} {details.get('url')} " \
                   f"{details.get('plugins') or ''}"
        else:
            subject = " ".join(filter(None, (subject, details.get("subphase") or "")))
            text = details.get("purpose") or details.get("summary") or \
                details.get("detail") or details.get("component") or ""
        print(f"{prefix}{subject}  {text}".rstrip(), file=self.stream)


class ScanEngine:
    """Execute a phase graph against a context and record every decision."""

    def __init__(self, context, graph=None, store=None, explain=False):
        self.ctx = context
        self.graph = graph or default_graph()
        self.store = store
        self.explain = explain
        self._unsubscribe = []

    # ---------------------------------------------------------------- plan
    def plan_lines(self):
        """[(phase, marker, note)] for `--plan`; argument gates are evaluated."""
        lines = []
        for phase in self.graph:
            marker, notes = "✓", []
            for pre in phase.preconditions:
                if pre.runtime:
                    notes.append(f"runtime: {pre.description}")
                elif not pre.check(self.ctx):
                    marker = "⊘"
                    notes.append(pre.skip_reason)
            lines.append((phase, marker, "; ".join(notes)))
        return lines

    # ----------------------------------------------------------------- run
    def begin(self, argv=()):
        if self.store is not None:
            self.ctx.run_id = self.store.create(self.ctx.target, argv)
            if self.ctx.run_id:
                self.ctx.run_dir = self.store.dir
                self._unsubscribe.append(self.store.attach(self.ctx.bus))
                # the engagement is part of the run's audit trail (roadmap 2.3)
                engagement = getattr(self.ctx, "engagement", None)
                if engagement is not None:
                    try:
                        engagement.save(self.store.dir / "engagement.json")
                    except Exception as exc:  # the scan never dies on bookkeeping
                        print(f"[*] Could not persist the engagement: {exc}")
        scan_events.set_sink(self.ctx.bus)
        if self.explain:
            self._unsubscribe.append(self.ctx.bus.subscribe(ExplainPrinter()))
        self.ctx.bus.emit(Event(EventType.RUN_STARTED, data={
            "target": self.ctx.target,
            "argv": list(argv),
            "wpbuddy_version": __version__,
            "run_id": self.ctx.run_id,
        }))

    def run(self):
        """Run the network phases; exceptions propagate to the caller."""
        for phase in self.graph.run_stage():
            self._run_phase(phase, rethrow=True)

    def finalize(self, status):
        """Run the finalize stage; always safe to call, even after a crash."""
        try:
            for phase in self.graph.finalize_stage():
                self._run_phase(phase, rethrow=False)
        finally:
            fail_reason = self.ctx.fail_reason
            if fail_reason:
                status = "failed-gate"
                print(f"[!] --fail-on {getattr(self.ctx.args, 'fail_on', 'none')}: {fail_reason}")
            self.ctx.bus.emit(Event(EventType.RUN_FINISHED, data={
                "status": status,
                "run_id": self.ctx.run_id,
                "fail_reason": fail_reason,
            }))
            if self.store is not None and self.store.dir is not None:
                self.store.finish({"status": status, "fail_reason": fail_reason})
            for unsubscribe in reversed(self._unsubscribe):
                unsubscribe()
            scan_events.clear_sink()
        return status

    def _skip_reasons(self, phase):
        reasons = []
        for pre in phase.preconditions:
            try:
                passed = pre.check(self.ctx)
            except Exception:
                passed = False
            if not passed:
                reasons.append(pre.skip_reason)
        return reasons

    def _run_phase(self, phase, rethrow):
        reasons = self._skip_reasons(phase)
        if reasons:
            self.ctx.statuses[phase.id] = "skipped"
            self.ctx.bus.emit(Event(EventType.PHASE_SKIPPED, phase.id, {"reasons": reasons}))
            return False

        handler = HANDLERS.get(phase.handler)
        if handler is None:
            self.ctx.statuses[phase.id] = "skipped"
            self.ctx.bus.emit(Event(EventType.PHASE_SKIPPED, phase.id,
                                    {"reasons": ["no handler registered"]}))
            return False

        self.ctx.statuses[phase.id] = "running"
        self.ctx.bus.emit(Event(EventType.PHASE_STARTED, phase.id, {
            "purpose": phase.purpose,
            "preconditions": [pre.description for pre in phase.preconditions],
            "effects": list(phase.effects),
        }))
        emit = self.ctx.bus.emitter(phase.id)
        purposes = {sub.id: sub.purpose for sub in phase.subphases}

        def emit_with_purpose(event_type, **data):
            if data.get("subphase") in purposes and "purpose" not in data:
                data["purpose"] = purposes[data["subphase"]]
            return emit(event_type, **data)

        try:
            handler(self.ctx, emit_with_purpose)
        except (KeyboardInterrupt, SystemExit):
            self.ctx.statuses[phase.id] = "interrupted"
            self.ctx.bus.emit(Event(EventType.PHASE_FAILED, phase.id,
                                    {"message": "interrupted"}))
            raise
        except TargetUnreachable:
            self.ctx.statuses[phase.id] = "unreachable"
            self.ctx.bus.emit(Event(EventType.PHASE_FAILED, phase.id,
                                    {"message": "target unreachable"}))
            raise
        except Exception as exc:
            self.ctx.statuses[phase.id] = "failed"
            self.ctx.bus.emit(Event(EventType.PHASE_FAILED, phase.id, {
                "message": f"{type(exc).__name__}: {exc}",
                "traceback": traceback.format_exc()[-4000:],
            }))
            if rethrow:
                raise
            return False
        else:
            self.ctx.statuses[phase.id] = "done"
            self.ctx.completed.add(phase.id)
            self.ctx.bus.emit(Event(EventType.PHASE_FINISHED, phase.id))
            return True
