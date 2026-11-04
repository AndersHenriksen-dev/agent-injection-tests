"""The free check of a skill or agent: what its file allows, read without calling a model.

Each rule looks at one risk and, if it applies, says why it matters and what to change. This file holds the logic of
the rules. What they look for and what they say is in the config file, where a fix can be corrected without touching
the code.
"""

from __future__ import annotations

import re

from injectiontests.lib.existing_agents.targets import base_tool, tools_with
from injectiontests.lib.shared.models import Capability, Finding, Severity, Strict, Target, TargetKind
from injectiontests.lib.shared.settings import config_for


class _Patterns(Strict):
    read_only_claim: str
    read_only_description: str
    data_rule_present: str
    secret: str
    side_effect_command: str
    broad_command: str


class _FindingText(Strict):
    severity: Severity
    title: str
    why: str
    fix: str


class _Advice(Strict):
    remove_from_skill: str
    keep_in_subagent: str
    remove_from_subagent: str
    remove_ways_out: str
    remove_shell_first: str
    check_commands: str


class _AuditConfig(Strict):
    patterns: _Patterns
    powerful_tools: frozenset[str]
    shell_tools: frozenset[str]
    data_rule: str
    advice: _Advice
    findings: dict[str, _FindingText]


_CONFIG = config_for(__name__, _AuditConfig)
_READ_ONLY_CLAIM = re.compile(_CONFIG.patterns.read_only_claim, re.IGNORECASE)
_READ_ONLY_DESCRIPTION = re.compile(_CONFIG.patterns.read_only_description, re.IGNORECASE)
_DATA_RULE_PRESENT = re.compile(_CONFIG.patterns.data_rule_present, re.IGNORECASE)
_SECRET = re.compile(_CONFIG.patterns.secret, re.IGNORECASE)
_SIDE_EFFECT_COMMAND = re.compile(_CONFIG.patterns.side_effect_command, re.IGNORECASE)
_BROAD_COMMAND = re.compile(_CONFIG.patterns.broad_command)
_SEVERITY_ORDER = {Severity.HIGH: 0, Severity.MEDIUM: 1, Severity.LOW: 2}


def _finding(name: str, **values: str) -> Finding:
    """A finding from its text in the config file, with the words in braces filled in."""
    text = _CONFIG.findings[name]
    return Finding(
        severity=text.severity,
        title=text.title.format(**values),
        why=text.why.format(**values),
        fix=text.fix.format(**values),
    )


def _join(tools: list[str]) -> str:
    return ", ".join(f"`{tool}`" for tool in tools) or "none"


def _is_broad_preapproval(entry: str) -> bool:
    """Whether an `allowed-tools` entry lets a powerful tool run almost anything without asking."""
    if base_tool(entry) not in _CONFIG.powerful_tools:
        return False
    if "(" not in entry:
        return True
    pattern = entry[entry.index("(") + 1 :].rstrip(")").strip()
    return not pattern or bool(_BROAD_COMMAND.match(pattern))


def _runs_unattended(target: Target, tools: list[str]) -> bool:
    """Whether any of these tools runs with no person able to say no."""
    if target.permission_mode == "bypassPermissions":
        return True
    broad = {base_tool(entry) for entry in target.preapproved if _is_broad_preapproval(entry)}
    return bool(broad & {base_tool(tool) for tool in tools})


def _how_to_remove(target: Target, tools: list[str]) -> str:
    names = ", ".join(base_tool(tool) for tool in tools)
    if target.kind is TargetKind.SKILL:
        return _CONFIG.advice.remove_from_skill.format(names=names)
    kept = [tool for tool in target.tools if base_tool(tool) not in {base_tool(t) for t in tools}]
    if kept:
        return _CONFIG.advice.keep_in_subagent.format(kept=", ".join(kept))
    return _CONFIG.advice.remove_from_subagent.format(names=names)


def _bypassed_permissions(target: Target) -> Finding | None:
    if target.permission_mode == "bypassPermissions":
        return _finding("bypassed_permissions")
    return _finding("accepted_edits") if target.permission_mode == "acceptEdits" else None


def _secret_in_instructions(target: Target) -> Finding | None:
    found = _SECRET.search(f"{target.description}\n{target.instructions}")
    return _finding("secret_in_instructions") if found else None


def _broad_preapprovals(target: Target) -> Finding | None:
    broad = [entry for entry in target.preapproved if _is_broad_preapproval(entry)]
    return _finding("broad_preapprovals", entries=_join(broad)) if broad else None


def _lethal_trifecta(target: Target) -> Finding | None:
    private = tools_with(target, Capability.READS_PRIVATE_DATA)
    outside = tools_with(target, Capability.READS_OUTSIDE_TEXT)
    ways_out = tools_with(target, Capability.SENDS_OUT)
    if not (private and outside and ways_out):
        return None
    shell = [tool for tool in ways_out if base_tool(tool) in _CONFIG.shell_tools]
    if shell:
        advice = _CONFIG.advice.remove_shell_first.format(remove=_how_to_remove(target, shell))
    else:
        advice = _CONFIG.advice.remove_ways_out.format(remove=_how_to_remove(target, ways_out))
    finding = _finding(
        "lethal_trifecta",
        private=_join(private),
        outside=_join(outside),
        ways_out=_join(ways_out),
        advice=advice,
    )
    return finding.model_copy(update={"severity": Severity.HIGH}) if _runs_unattended(target, ways_out) else finding


def _no_tool_limit(target: Target) -> Finding | None:
    if target.kind is not TargetKind.SUBAGENT or target.tools_listed:
        return None
    return _finding("no_tool_limit")


def _read_only_claim(target: Target) -> Finding | None:
    changing = tools_with(target, Capability.CHANGES_THINGS)
    claims = _READ_ONLY_DESCRIPTION.search(target.description) or _READ_ONLY_CLAIM.search(
        f"{target.description}\n{target.instructions}",
    )
    if not changing or not claims:
        return None
    advice = _how_to_remove(target, changing)
    if any(base_tool(tool) in _CONFIG.shell_tools for tool in changing):
        advice = _CONFIG.advice.check_commands.format(remove=advice)
    return _finding("read_only_claim", changing=_join(changing), advice=advice)


def _auto_invoked_side_effects(target: Target) -> Finding | None:
    if target.kind is not TargetKind.SKILL or not target.model_invocable:
        return None
    commands = sorted({match.group(0).lower() for match in _SIDE_EFFECT_COMMAND.finditer(target.instructions)})
    return _finding("auto_invoked_side_effects", commands=_join(commands)) if commands else None


def _whole_server(target: Target) -> Finding | None:
    wildcards = [tool for tool in target.tools if "*" in base_tool(tool)]
    return _finding("whole_server", wildcards=_join(wildcards)) if wildcards else None


def _no_data_rule(target: Target) -> Finding | None:
    if not tools_with(target, Capability.READS_OUTSIDE_TEXT) or _DATA_RULE_PRESENT.search(target.instructions):
        return None
    return _finding("no_data_rule", data_rule=_CONFIG.data_rule)


def audit(target: Target) -> list[Finding]:
    """Everything to fix in a target's file, most severe first."""
    rules = [
        _bypassed_permissions,
        _secret_in_instructions,
        _broad_preapprovals,
        _lethal_trifecta,
        _no_tool_limit,
        _read_only_claim,
        _auto_invoked_side_effects,
        _whole_server,
        _no_data_rule,
    ]
    findings = [finding for rule in rules if (finding := rule(target)) is not None]
    return sorted(findings, key=lambda finding: _SEVERITY_ORDER[finding.severity])
