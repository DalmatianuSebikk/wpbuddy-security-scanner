"""The scan phase graph: one declarative source of truth for order and docs.

Both the CLI and the future TUI walk this graph. A phase is never skipped
because of an `if` buried in the orchestrator: every skip is a named
precondition with a human-readable reason, which is exactly what the flow
observatory renders (`⊘ code-audit — --audit-code off`).

The graph is split into two stages:

* ``run``       - network work, executed inside the crash guard;
* ``finalize``  - WAF/error-page analysis and report writing, executed from
                  ``finally`` so a crashed scan still yields a partial report.

Purposes are short, operator-facing sentences. They double as the TUI help
text and are covered by a test, so a new phase cannot ship undocumented.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class SubphaseSpec:
    """A named step inside a phase (a check the observatory can show)."""

    id: str
    title: str
    purpose: str


@dataclass(frozen=True)
class Precondition:
    """A named gate. ``runtime`` means it can only be decided during the run."""

    id: str
    description: str
    check: Callable[[Any], bool]
    skip_reason: str
    runtime: bool = False


@dataclass(frozen=True)
class PhaseSpec:
    """One step of the graph plus everything needed to explain it."""

    id: str
    title: str
    purpose: str
    handler: str
    stage: str = "run"
    preconditions: tuple[Precondition, ...] = field(default_factory=tuple)
    inputs: tuple[str, ...] = field(default_factory=tuple)
    outputs: tuple[str, ...] = field(default_factory=tuple)
    effects: tuple[str, ...] = ("network",)
    reversible: bool = True
    subphases: tuple[SubphaseSpec, ...] = field(default_factory=tuple)


class PhaseGraph:
    """Ordered phases with two stages and lookup by id."""

    def __init__(self, phases):
        self._phases = tuple(phases)
        seen = set()
        for phase in self._phases:
            if phase.id in seen:
                raise ValueError(f"duplicate phase id: {phase.id}")
            seen.add(phase.id)
            if phase.stage not in ("run", "finalize"):
                raise ValueError(f"unknown stage for {phase.id}: {phase.stage}")

    def __iter__(self):
        return iter(self._phases)

    def __len__(self):
        return len(self._phases)

    def __contains__(self, phase_id):
        return any(phase.id == phase_id for phase in self._phases)

    def get(self, phase_id):
        for phase in self._phases:
            if phase.id == phase_id:
                return phase
        raise KeyError(phase_id)

    def stage(self, name):
        return tuple(phase for phase in self._phases if phase.stage == name)

    def run_stage(self):
        return self.stage("run")

    def finalize_stage(self):
        return self.stage("finalize")

    def ids(self):
        return tuple(phase.id for phase in self._phases)


# --------------------------------------------------------------------------
# Preconditions. Argument-only gates are decidable for `--plan`; the rest are
# marked runtime and evaluated against the ScanContext while running.
# --------------------------------------------------------------------------

def _arg(args, name, default=None):
    return getattr(args, name, default)


_TARGET_ALIVE = Precondition(
    "target-alive", "the liveness probe reached the target",
    lambda ctx: bool(ctx.alive), "target unreachable", runtime=True)

_LIVENESS_DONE = Precondition(
    "liveness-done", "the liveness probe completed",
    lambda ctx: "liveness" in ctx.completed, "liveness did not complete",
    runtime=True)

_NOT_STEALTH = Precondition(
    "not-stealth", "--stealth runs the passive phase only",
    lambda ctx: not _arg(ctx.args, "stealth", False),
    "--stealth (passive phase only)")

_ACCESS_REQUESTED = Precondition(
    "access-requested", "--access or --user opted into credential testing",
    lambda ctx: bool(_arg(ctx.args, "access", False) or _arg(ctx.args, "user")),
    "credential testing is opt-in (--access / --user)")

_ACTIVE_DONE = Precondition(
    "active-done", "user enumeration and XML-RPC probing completed",
    lambda ctx: "active" in ctx.completed, "the active phase did not complete",
    runtime=True)

_AUDIT_ENABLED = Precondition(
    "audit-enabled", "the code audit was not switched off",
    lambda ctx: _arg(ctx.args, "audit_code", "off") != "off",
    "--audit-code off")


def default_graph():
    """The canonical WpBuddy phase order."""
    return PhaseGraph([
        PhaseSpec(
            "liveness", "Liveness", "verify the target answers before spending further requests",
            handler="liveness", effects=("none",),
            inputs=("target",), outputs=("alive-socket",),
            subphases=(SubphaseSpec("probe", "Homepage probe",
                                    "one cheap request distinguishes dead from live"),)),

        PhaseSpec(
            "passive", "Passive recon", "GET-only recon: core/theme/plugin inventory, "
            "exposure and vulnerability matching",
            handler="passive", preconditions=(_TARGET_ALIVE,),
            inputs=("target",), outputs=("components", "versions", "findings"),
            subphases=(
                SubphaseSpec("rest-discovery", "REST discovery",
                             "read /wp-json/ namespaces as plugin fingerprints"),
                SubphaseSpec("crawl", "Crawl", "collect same-site pages within --max-pages"),
                SubphaseSpec("references", "References",
                             "extract component URLs and inline-script artifacts"),
                SubphaseSpec("asset-versions", "Asset versions",
                             "harvest ?ver= values when readmes are unreadable"),
                SubphaseSpec("core-version", "Core version",
                             "identify WordPress core from independent sources"),
                SubphaseSpec("plugins", "Plugins",
                             "combine references, fingerprints, enumeration and readmes"),
                SubphaseSpec("themes", "Themes", "identify the active theme from crawled pages"),
                SubphaseSpec("rest", "REST report", "report exposed plugin REST namespaces"),
                SubphaseSpec("robots", "robots.txt", "read robots for paths and sitemaps"),
                SubphaseSpec("security-txt", "security.txt", "read the disclosure contact"),
                SubphaseSpec("sensitive-files", "Sensitive files",
                             "probe debug.log, readme and backup-ish paths"),
                SubphaseSpec("setup-wizard", "Setup wizard",
                             "detect an unfinished install wizard"),
                SubphaseSpec("headers", "Security headers",
                             "check the response header policy for the scheme"),
                SubphaseSpec("dangling", "Dangling hosts",
                             "resolve referenced external hosts for takeover signs"),
                SubphaseSpec("posture", "Posture", "TLS and email/DNS posture checks"),
                SubphaseSpec("extra-checks", "Extra passive checks",
                             "wp-cron, CORS, cookie flags, heartbeat exposure"),
                SubphaseSpec("auth-check", "Authenticated check",
                             "identity/capability mapping when credentials were supplied"),
            )),

        PhaseSpec(
            "active", "Active probing", "quiet POSTs: user enumeration, XML-RPC and extra checks",
            handler="active", preconditions=(_NOT_STEALTH, _LIVENESS_DONE),
            inputs=("target", "passive inventory"), outputs=("users", "xmlrpc state"),
            subphases=(
                SubphaseSpec("users", "User enumeration",
                             "REST, author archives and login errors within --max-users"),
                SubphaseSpec("xmlrpc", "XML-RPC probe", "detect the XML-RPC surface"),
                SubphaseSpec("extra-checks", "Extra active checks",
                             "install/upgrade remnats, heartbeat, pingback"),
            )),

        PhaseSpec(
            "access", "Access assessment", "open registration, username validation and "
            "targeted password spray",
            handler="access", preconditions=(_NOT_STEALTH, _ACCESS_REQUESTED, _ACTIVE_DONE),
            inputs=("target", "validated users", "password candidates"),
            outputs=("credentials",),
            subphases=(
                SubphaseSpec("registration", "Registration",
                             "check whether self-registration is open"),
                SubphaseSpec("username-validation", "Username validation",
                             "confirm accounts through the login error differential"),
                SubphaseSpec("password-spray", "Password spray",
                             "one high-probability password per user per round"),
            )),

        PhaseSpec(
            "code-audit", "Code audit", "gather component source (listing/wordpress.org/"
            "operator archive) and analyze it locally",
            handler="code-audit",
            preconditions=(_AUDIT_ENABLED, _LIVENESS_DONE),
            inputs=("components", "versions"), outputs=("rule findings", "PoC pack", "artifacts"),
            subphases=(
                SubphaseSpec("gather", "Gather source",
                             "mirror a listing, fetch the exact official version or use --source-dir"),
                SubphaseSpec("analyze", "Pattern analysis", "run the PHP rule engine"),
                SubphaseSpec("malware", "Malware/secret scan", "webshell markers, decode chains, secrets"),
                SubphaseSpec("semgrep", "Semgrep", "optional bundled Semgrep rule pack"),
                SubphaseSpec("verify", "PoC verification",
                             "benign live payloads for verifiable findings"),
                SubphaseSpec("dependencies", "Bundled dependencies", "composer/package inventory + advisories"),
                SubphaseSpec("integrity", "Integrity", "deployed mirror vs official archive diff"),
                SubphaseSpec("report", "Audit report", "per-component findings and evidence"),
            )),

        PhaseSpec(
            "waf-analysis", "WAF analysis", "write what the firewall revealed and which bypasses worked",
            handler="waf-analysis", stage="finalize", effects=("none",),
            inputs=("waf events",), outputs=("report section",)),

        PhaseSpec(
            "error-analysis", "Error analysis", "write collected PHP error pages and their disclosure",
            handler="error-analysis", stage="finalize", effects=("none",),
            inputs=("error pages",), outputs=("report section",)),

        PhaseSpec(
            "report", "Report", "priorities, diff, executive summary, --fail-on gate and output files",
            handler="report", stage="finalize", effects=("filesystem",),
            inputs=("model", "report body", "run metadata"), outputs=("markdown", "json", "exit gate"),
            subphases=(
                SubphaseSpec("priorities", "Remediation priorities", "risk-ranked fix order"),
                SubphaseSpec("diff", "Previous-run diff", "new/resolved findings against --diff"),
                SubphaseSpec("summary", "Executive summary", "counts, metadata and top risks"),
                SubphaseSpec("fail-on", "Fail-on gate", "translate findings into an exit code"),
                SubphaseSpec("write", "Write outputs", "Markdown report and optional JSON graph"),
            )),
    ])
