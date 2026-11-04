"""The defenses that are compared: prompt rules, marking tool output as data, and guards in code."""

from __future__ import annotations

from anthropic.types import ToolParam

from injectiontests.lib.fund_agent.guards import Approval, Egress, Guard, LeastPrivilege, host_of, is_company_host
from injectiontests.lib.fund_agent.world import TOOLS
from injectiontests.lib.shared.models import Strict, Task, World
from injectiontests.lib.shared.settings import config_for


class Defense(Strict):
    """One configuration of the agent: which prompt and which guards it runs with."""

    name: str
    description: str
    prompt_rules: bool = False
    spotlight: bool = False
    least_privilege: bool = False
    approval: bool = False
    egress: bool = False


class _DefensesConfig(Strict):
    base_prompt: str
    rules: str
    spotlight_rules: str
    tag: str
    defenses: list[Defense]


_CONFIG = config_for(__name__, _DefensesConfig)
TAG = _CONFIG.tag
DEFENSES: dict[str, Defense] = {defense.name: defense for defense in _CONFIG.defenses}


def system_prompt(defense: Defense) -> str:
    """The system prompt for a defense."""
    parts = [_CONFIG.base_prompt]
    if defense.prompt_rules:
        parts.append(_CONFIG.rules)
    if defense.spotlight:
        parts.append(_CONFIG.spotlight_rules)
    return "\n\n".join(parts)


def offered_tools(defense: Defense, task: Task) -> list[ToolParam]:
    """The tools the model is shown, in a fixed order so the prompt cache stays valid."""
    names = task.tools if defense.least_privilege else list(TOOLS)
    return [TOOLS[name] for name in TOOLS if name in names]


def allowed_hosts(task: Task, world: World) -> set[str]:
    """Outside hosts the task itself needs to fetch from."""
    hosts = {host_of(action.arguments.get("url", "")) for action in task.allowed_actions if action.tool == "fetch_url"}
    return {host for host in hosts if host and not is_company_host(host, world.company_domain)}


def egress_guard(task: Task, world: World) -> Egress:
    """The egress guard for a task: company addresses and hosts, the task's own sites, and all known secrets."""
    secrets = [*world.secrets, *(client.account for client in world.clients.values())]
    return Egress(world.company_domain, allowed_hosts(task, world), secrets)


def guards_for(defense: Defense, task: Task, world: World) -> list[Guard]:
    """The guards a defense runs for a task, in the order they are checked."""
    guards: list[Guard] = []
    if defense.least_privilege:
        guards.append(LeastPrivilege(task.tools))
    if defense.egress:
        guards.append(egress_guard(task, world))
    if defense.approval:
        guards.append(Approval(task.allowed_actions))
    return guards


def wrap_output(defense: Defense, tool: str, output: str) -> str:
    """Mark a tool result as data, with any copy of the tag inside it broken so it cannot close the wrapper early."""
    if not defense.spotlight:
        return output
    escaped = output.replace(f"<{TAG}", f"<{TAG}_").replace(f"</{TAG}", f"</{TAG}_")
    return f'<{TAG} tool="{tool}">\n{escaped}\n</{TAG}>'


def filter_answer(defense: Defense, task: Task, world: World, text: str) -> str:
    """The answer the employee sees: with the egress defense, links to outside hosts are removed."""
    return egress_guard(task, world).filter_answer(text) if defense.egress else text
