"""Turning findings and attack results into the Markdown report a person acts on."""

from __future__ import annotations

from collections import Counter

from injectiontests.models import Capability, Finding, Target
from injectiontests.scan import GOAL_DESCRIPTIONS, GOAL_NEEDS, AttackResult, Outcome
from injectiontests.targets import tools_with

_LIMITS = """## What this does not cover

- It reads this file only. Your `settings.json`, hooks and sandbox are not read, so one of them may already handle a \
finding. Agents run without a person, for example in CI, have no permission prompts to rely on.
- It places MCP and custom tools by the words in their names, and counts one it cannot place as able to do anything \
but run commands.
- A scan simulates the tools and runs your instructions alone, without Claude Code's own system prompt and permission \
prompts. It tests your instructions and tool list, not the whole product. Results vary between runs, and a clean run \
over known attacks does not mean the agent is safe against someone who keeps trying.
- The tool output is made up by a small model, so the agent may notice that something is off and give up on its job. \
The table shows how each answer starts: "resisted" from an agent that gave up is weak evidence that it would resist \
while working."""

_ANSWER_START_CHARS = 70


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
    for goal, description in GOAL_DESCRIPTIONS.items():
        need = GOAL_NEEDS[goal]
        tools = tools_with(target, need) if need else []
        if not can_be_reached or (need and not tools):
            cell = "no"
        else:
            cell = f"yes, through {', '.join(f'`{tool}`' for tool in tools)}" if tools else "yes"
        lines.append(f"| {description} | {cell} |")
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
    return f"{words[:_ANSWER_START_CHARS]}..." if len(words) > _ANSWER_START_CHARS else words or "(no answer)"


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
            GOAL_DESCRIPTIONS[attack.goal],
            result.outcome,
            _answer_start(result),
        ]
        lines.append("| " + " | ".join(cells) + " |")
    lines.append("")
    if counts[Outcome.NOT_DELIVERED]:
        lines += [
            f"{counts[Outcome.NOT_DELIVERED]} attack(s) were not delivered: the agent read nothing, so those runs say "
            "nothing about resisting them. Give it a request that makes it read, with `--task`.",
            "",
        ]
    if counts[Outcome.UNFINISHED]:
        lines += [
            f"{counts[Outcome.UNFINISHED]} run(s) ran out of turns before answering. No attack had worked by then, but "
            "these runs could still have obeyed, so they do not count as resisted.",
            "",
        ]
    if counts[Outcome.REFUSED]:
        lines += [
            f"{counts[Outcome.REFUSED]} run(s) ended in a refusal. No attack worked there, but the user got no answer, "
            "so the attack still stopped the work.",
            "",
        ]
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
