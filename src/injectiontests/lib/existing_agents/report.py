"""Turning findings and attack results into the Markdown report a person acts on."""

from __future__ import annotations

from collections import Counter

from injectiontests.lib.existing_agents.scan import GOALS, AttackResult, Outcome
from injectiontests.lib.existing_agents.targets import tools_with
from injectiontests.lib.shared.models import Capability, Finding, Strict, Target
from injectiontests.lib.shared.settings import config_for


class _ReportConfig(Strict):
    answer_start_chars: int
    not_delivered: str
    unfinished: str
    refused: str
    limits: list[str]


_CONFIG = config_for(__name__, _ReportConfig)
_LIMITS = "\n".join(["## What this does not cover", "", *(f"- {limit}" for limit in _CONFIG.limits)])


def _header(target: Target) -> list[str]:
    tools = ", ".join(f"`{tool}`" for tool in target.tools) or "none"
    limit = "" if target.tools_listed else " (not limited by its file)"
    return [f"# Injection report: {target.name}", "", f"`{target.path}`, {target.kind}. Tools{limit}: {tools}.", ""]


def _reach_table(target: Target) -> list[str]:
    """What an attacker could reach if the model were fully fooled, which depends only on the tools."""
    lines = [
        "## If the model is fooled, an attacker could",
        "",
        "| Goal | Reachable |",
        "|---|---|",
    ]
    can_be_reached = bool(tools_with(target, Capability.READS_OUTSIDE_TEXT))
    for goal in GOALS.values():
        need = goal.needs
        tools = tools_with(target, need) if need else []
        if not can_be_reached or (need and not tools):
            cell = "no"
        else:
            cell = f"yes, through {', '.join(f'`{tool}`' for tool in tools)}" if tools else "yes"
        lines.append(f"| {goal.description} | {cell} |")
    if not can_be_reached:
        lines += [
            "",
            "It has no tool that reads outside text, so a planted instruction cannot reach it through a tool.",
        ]
    return [*lines, ""]


def _findings_section(findings: list[Finding]) -> list[str]:
    lines = ["## What to fix", ""]
    if not findings:
        return [*lines, "Nothing to fix was found.", ""]
    for number, finding in enumerate(findings, start=1):
        lines += [
            f"{number}. **[{finding.severity}] {finding.title}.**",
            f"   - Why: {finding.why}",
            f"   - Fix: {finding.fix}",
        ]
    return [*lines, ""]


def audit_report(target: Target, findings: list[Finding]) -> str:
    """The report of the free check."""
    return "\n".join([*_header(target), *_findings_section(findings), *_reach_table(target), _LIMITS, ""])


def _answer_start(result: AttackResult) -> str:
    """The start of the answer, on one line, so that a person can see at a glance whether the agent did its job."""
    words = " ".join(result.transcript.final_answer.split()).replace("|", "/")
    limit = _CONFIG.answer_start_chars
    return f"{words[:limit]}..." if len(words) > limit else words or "(no answer)"


def _results_section(results: list[AttackResult], model: str, task: str, emulator_cost_usd: float) -> list[str]:
    counts = Counter(result.outcome for result in results)
    total = sum(result.transcript.cost_usd for result in results)
    summary = ", ".join(f"{counts[outcome]} {outcome}" for outcome in Outcome if counts[outcome])
    cost = f"USD {total:.4f}, plus USD {emulator_cost_usd:.4f} for the simulated tool output"
    lines = [
        "## Attacks on a real model",
        "",
        f"{len(results)} runs with {model}, {cost}: {summary or 'nothing ran'}.",
        "",
        f"Request given to the agent: {task}",
        "",
        "| Attack | Technique | Goal | Result | The answer starts |",
        "|---|---|---|---|---|",
    ]
    for result in results:
        attack = result.attack
        cells = [
            f"`{attack.id}`",
            attack.technique,
            GOALS[attack.goal].description,
            result.outcome,
            _answer_start(result),
        ]
        lines.append("| " + " | ".join(cells) + " |")
    lines.append("")
    for outcome, explanation in [
        (Outcome.NOT_DELIVERED, _CONFIG.not_delivered),
        (Outcome.UNFINISHED, _CONFIG.unfinished),
        (Outcome.REFUSED, _CONFIG.refused),
    ]:
        if counts[outcome]:
            lines += [explanation.format(count=counts[outcome]), ""]
    return lines


def scan_report(
    target: Target,
    findings: list[Finding],
    results: list[AttackResult],
    model: str,
    task: str,
    emulator_cost_usd: float,
) -> str:
    """The report of the paid test: what its file allows, and what the attacks did."""
    sections = [
        *_header(target),
        *_findings_section(findings),
        *_results_section(results, model, task, emulator_cost_usd),
        *_reach_table(target),
        _LIMITS,
        "",
    ]
    return "\n".join(sections)
