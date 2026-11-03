"""The agent loop: the model asks for tools, the guards decide, the tools run, the model reads the results.

The loop is written by hand rather than with the SDK's tool runner, because every call has to pass the guards and be
recorded before it runs, whether or not it is then allowed.
"""

from __future__ import annotations

import time
from typing import Protocol

import anthropic
from anthropic.types import Message, MessageParam, ToolParam, ToolResultBlockParam, ToolUseBlock
from anthropic.types import Usage as ApiUsage

from injectiontests.config import MAX_TOKENS, MAX_TURNS, PRICES, Effort
from injectiontests.defenses import Defense, filter_answer, guards_for, offered_tools, system_prompt, wrap_output
from injectiontests.guards import Guard
from injectiontests.models import Attack, PlannedCall, Task, ToolCall, Transcript, Usage, World
from injectiontests.world import ToolError, Workspace, plant


class Model(Protocol):
    """Something that answers one turn of the conversation, like the Messages API."""

    name: str

    def respond(self, *, system: str, tools: list[ToolParam], messages: list[MessageParam]) -> Message:
        """Return the model's next message."""
        ...


class ClaudeModel:
    """A Claude model through the Messages API."""

    def __init__(self, client: anthropic.Anthropic, name: str, effort: Effort) -> None:
        """Use `client` to call model `name` at `effort`."""
        self.client = client
        self.name = name
        self.effort: Effort = effort

    def respond(self, *, system: str, tools: list[ToolParam], messages: list[MessageParam]) -> Message:
        """One Messages API call. The tools and system prompt are cached, since they repeat every turn."""
        return self.client.messages.create(
            model=self.name,
            max_tokens=MAX_TOKENS,
            system=[{"type": "text", "text": system, "cache_control": {"type": "ephemeral"}}],
            tools=tools,
            messages=messages,
            output_config={"effort": self.effort},
        )


class ScriptedModel:
    """A model that makes a fixed list of tool calls, one per turn, then gives a fixed answer.

    With an attack's `attacker_calls` it is a fully hijacked model: the worst case the guards must hold against. With a
    task's `reference_calls` it is a model that does the job right, which shows whether a guard blocks real work.
    """

    def __init__(self, calls: list[PlannedCall], answer: str) -> None:
        """Make `calls` in order, skipping any tool the model is not offered, then answer `answer`."""
        self.name = "scripted"
        self.calls = calls
        self.answer = answer

    def respond(self, *, system: str, tools: list[ToolParam], messages: list[MessageParam]) -> Message:
        """The next planned call the model can make, or the final answer once none are left."""
        offered = {tool["name"] for tool in tools}
        made = sum(1 for message in messages if message["role"] == "assistant")
        remaining = [call for call in self.calls if call.tool in offered][made:]
        if remaining:
            content: list[dict[str, object]] = [
                {"type": "tool_use", "id": f"toolu_{made}", "name": remaining[0].tool, "input": remaining[0].arguments},
            ]
            stop_reason = "tool_use"
        else:
            content = [{"type": "text", "text": self.answer}]
            stop_reason = "end_turn"
        return Message.model_validate(
            {
                "id": f"msg_scripted_{made}",
                "type": "message",
                "role": "assistant",
                "model": self.name,
                "content": content,
                "stop_reason": stop_reason,
                "stop_sequence": None,
                "usage": {"input_tokens": 0, "output_tokens": 0},
            },
        )


def cost_usd(model: str, usage: Usage) -> float:
    """What a run cost at list prices. Unknown models, such as the scripted one, cost nothing."""
    if model not in PRICES:
        return 0.0
    input_price, output_price = PRICES[model]
    total = (
        usage.input_tokens * input_price
        + usage.cache_read_tokens * input_price * 0.1
        + usage.cache_write_tokens * input_price * 1.25
        + usage.output_tokens * output_price
    )
    return total / 1_000_000


def _add_usage(total: Usage, usage: ApiUsage) -> None:
    total.input_tokens += usage.input_tokens
    total.output_tokens += usage.output_tokens
    total.cache_read_tokens += usage.cache_read_input_tokens or 0
    total.cache_write_tokens += usage.cache_creation_input_tokens or 0


def _final_text(message: Message) -> str:
    return "\n".join(block.text for block in message.content if block.type == "text").strip()


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
    tools = offered_tools(defense, task)
    system = system_prompt(defense)
    messages: list[MessageParam] = [{"role": "user", "content": task.prompt}]
    transcript = Transcript(task=task.id, attack=attack.id if attack else None, defense=defense.name, model=model.name)
    started = time.perf_counter()

    for _ in range(MAX_TURNS):
        response = model.respond(system=system, tools=tools, messages=messages)
        transcript.turns += 1
        _add_usage(transcript.usage, response.usage)
        if response.stop_reason == "refusal":
            transcript.refused = True
            break
        # The whole content goes back unchanged, thinking blocks included, as the API requires.
        messages.append({"role": "assistant", "content": response.content})
        uses = [block for block in response.content if block.type == "tool_use"]
        if not uses:
            transcript.final_answer = _final_text(response)
            break
        results: list[ToolResultBlockParam] = []
        for block in uses:
            call, result = handle_tool_use(block, guards, workspace, defense)
            transcript.calls.append(call)
            results.append(result)
        messages.append({"role": "user", "content": results})

    transcript.shown_answer = filter_answer(defense, task, world, transcript.final_answer)
    transcript.seconds = round(time.perf_counter() - started, 2)
    transcript.cost_usd = cost_usd(model.name, transcript.usage)
    return transcript
