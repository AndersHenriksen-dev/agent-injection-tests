"""One run of the fund agent: every call passes the guards and is recorded before it runs."""

from __future__ import annotations

from anthropic.types import ToolResultBlockParam, ToolUseBlock

from injectiontests.lib.fund_agent.defenses import (
    Defense,
    filter_answer,
    guards_for,
    offered_tools,
    system_prompt,
    wrap_output,
)
from injectiontests.lib.fund_agent.guards import Guard
from injectiontests.lib.fund_agent.world import ToolError, Workspace, plant
from injectiontests.lib.shared.loop import Model, run_turns
from injectiontests.lib.shared.models import Attack, Task, ToolCall, Transcript, World


def handle_tool_use(
    block: ToolUseBlock,
    guards: list[Guard],
    workspace: Workspace,
    defense: Defense,
) -> tuple[ToolCall, ToolResultBlockParam]:
    """Check one tool call against the guards, run it if they allow it, and build the result for the model."""
    arguments = dict(block.input) if isinstance(block.input, dict) else {}
    call = ToolCall(tool=block.name, arguments=arguments)
    blocked = next(((guard, decision) for guard in guards if not (decision := guard.check(call)).allowed), None)
    if blocked is not None:
        guard, decision = blocked
        call.blocked_by = guard.name
        call.output = f"Blocked: {decision.reason}"
        content = call.output
    else:
        try:
            call.output = workspace.execute(call.tool, call.arguments)
            call.executed = True
            content = wrap_output(defense, call.tool, call.output)
        except ToolError as error:
            call.output = f"Error: {error}"
            content = call.output
    result: ToolResultBlockParam = {
        "type": "tool_result",
        "tool_use_id": block.id,
        "content": content,
        "is_error": not call.executed,
    }
    return call, result


def run(model: Model, world: World, task: Task, attack: Attack | None, defense: Defense) -> Transcript:
    """Run one task, with the attack planted if there is one, under one defense."""
    workspace = Workspace(plant(world, attack) if attack else world)
    guards = guards_for(defense, task, world)
    transcript = Transcript(task=task.id, attack=attack.id if attack else None, defense=defense.name, model=model.name)
    run_turns(
        model,
        transcript,
        system_prompt(defense),
        offered_tools(defense, task),
        task.prompt,
        lambda block: handle_tool_use(block, guards, workspace, defense),
    )
    transcript.shown_answer = filter_answer(defense, task, world, transcript.final_answer)
    return transcript
