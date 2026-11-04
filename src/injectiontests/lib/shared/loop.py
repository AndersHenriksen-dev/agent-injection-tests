"""The agent loop: the model asks for tools, something handles each call, the model reads the results.

The loop is written by hand rather than with the SDK's tool runner, because every call has to be checked and recorded
before it runs, whether or not it is then allowed. What a call does is up to the caller: the fund agent runs it through
its guards, and a scan answers it with simulated tools.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from typing import Protocol

import anthropic
from anthropic.types import Message, MessageParam, ToolParam, ToolResultBlockParam, ToolUseBlock
from anthropic.types import Usage as ApiUsage
from dotenv import find_dotenv, load_dotenv

from injectiontests.lib.shared.models import PlannedCall, ToolCall, Transcript, Usage
from injectiontests.lib.shared.settings import SETTINGS, Effort


class Model(Protocol):
    """Something that answers one turn of the conversation, like the Messages API."""

    name: str

    def respond(self, *, system: str, tools: list[ToolParam], messages: list[MessageParam]) -> Message:
        """Return the model's next message."""
        ...


def claude_client() -> anthropic.Anthropic:
    """An API client, with its key from the environment or a .env file in the folder the command runs from."""
    load_dotenv(find_dotenv(usecwd=True))
    return anthropic.Anthropic()


class ClaudeModel:
    """A Claude model through the Messages API."""

    def __init__(self, client: anthropic.Anthropic, name: str, effort: Effort, cache_conversation: bool = True) -> None:
        """Use `client` to call model `name` at `effort`.

        Args:
            client: The API client.
            name: The model id.
            effort: The effort level.
            cache_conversation: Cache the conversation as it grows. Turn it off for one-off prompts, which never read
                that cache back and would only pay to write it.
        """
        self.client = client
        self.name = name
        self.effort: Effort = effort
        self.cache_conversation = cache_conversation

    def respond(self, *, system: str, tools: list[ToolParam], messages: list[MessageParam]) -> Message:
        """One Messages API call. The tools and system prompt are cached, since they repeat every turn."""
        return self.client.messages.create(
            model=self.name,
            max_tokens=SETTINGS.max_tokens,
            system=[{"type": "text", "text": system, "cache_control": {"type": "ephemeral"}}],
            tools=tools,
            messages=messages,
            output_config={"effort": self.effort},
            cache_control={"type": "ephemeral"} if self.cache_conversation else anthropic.omit,
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


def strict_tool(name: str, description: str, properties: dict[str, str]) -> ToolParam:
    """A strict tool definition whose parameters are all required strings."""
    return {
        "name": name,
        "description": description,
        "strict": True,
        "input_schema": {
            "type": "object",
            "properties": {key: {"type": "string", "description": text} for key, text in properties.items()},
            "required": list(properties),
            "additionalProperties": False,
        },
    }


def cost_usd(model: str, usage: Usage) -> float:
    """What a run cost at list prices. Unknown models, such as the scripted one, cost nothing."""
    if model not in SETTINGS.prices:
        return 0.0
    price = SETTINGS.prices[model]
    total = (
        usage.input_tokens * price.input
        + usage.cache_read_tokens * price.cache_read
        + usage.cache_write_tokens * price.input * SETTINGS.cache_write_multiplier
        + usage.output_tokens * price.output
    )
    return total / 1_000_000


def add_usage(total: Usage, usage: ApiUsage) -> None:
    """Add one response's tokens to a running total."""
    total.input_tokens += usage.input_tokens
    total.output_tokens += usage.output_tokens
    total.cache_read_tokens += usage.cache_read_input_tokens or 0
    total.cache_write_tokens += usage.cache_creation_input_tokens or 0


def final_text(message: Message) -> str:
    """The text of a message, without its thinking and tool calls."""
    return "\n".join(block.text for block in message.content if block.type == "text").strip()


def run_turns(
    model: Model,
    transcript: Transcript,
    system: str,
    tools: list[ToolParam],
    prompt: str,
    handle: Callable[[ToolUseBlock], tuple[ToolCall, ToolResultBlockParam]],
    max_turns: int = SETTINGS.max_turns,
) -> None:
    """The loop itself: ask the model, hand each tool call to `handle`, and record everything in `transcript`."""
    messages: list[MessageParam] = [{"role": "user", "content": prompt}]
    started = time.perf_counter()

    for _ in range(max_turns):
        response = model.respond(system=system, tools=tools, messages=messages)
        transcript.turns += 1
        add_usage(transcript.usage, response.usage)
        if response.stop_reason == "refusal":
            transcript.refused = True
            break
        # The whole content goes back unchanged, thinking blocks included, as the API requires.
        messages.append({"role": "assistant", "content": response.content})
        uses = [block for block in response.content if block.type == "tool_use"]
        if not uses:
            transcript.final_answer = final_text(response)
            break
        results: list[ToolResultBlockParam] = []
        for block in uses:
            call, result = handle(block)
            transcript.calls.append(call)
            results.append(result)
        messages.append({"role": "user", "content": results})

    transcript.seconds = round(time.perf_counter() - started, 2)
    transcript.cost_usd = cost_usd(model.name, transcript.usage)
