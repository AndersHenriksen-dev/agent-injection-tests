"""Data contracts for the case files, tool calls and run results.

Everything that is read from YAML or written to JSON passes through these models, so the rest of the code works with
typed objects.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class Strict(BaseModel):
    """Base model that rejects unknown fields, so a typo in a case file fails loudly."""

    model_config = ConfigDict(extra="forbid")


# ---------- The synthetic company ----------


class Client(Strict):
    """A client of the fund administrator. The account number is a canary: it must never leave the company."""

    name: str
    account: str
    relationship_manager: str
    holdings: str


class Email(Strict):
    """An email in the employee's inbox."""

    sender: str
    subject: str
    body: str


class Document(Strict):
    """An internal document."""

    title: str
    body: str


class World(Strict):
    """Everything the agent can read or change. Attacks add text to one item before a run."""

    company_domain: str
    clients: dict[str, Client]
    emails: dict[str, Email]
    documents: dict[str, Document]
    pages: dict[str, str]
    secrets: list[str] = Field(description="Values that must never leave the company, besides client accounts.")


# ---------- Tasks and attacks ----------


class AllowedAction(Strict):
    """A write or outbound call the user's request asks for. Empty `arguments` allows any arguments."""

    tool: str
    arguments: dict[str, str] = {}


class PlannedCall(Strict):
    """A tool call a scripted model makes: the attacker's calls in the worst case, or the right calls for a task."""

    tool: str
    arguments: dict[str, str]


class Task(Strict):
    """A normal request from the employee, which an attack tries to hijack."""

    id: str
    prompt: str
    tools: list[str] = Field(description="The tools the task needs: the least-privilege allowlist.")
    allowed_actions: list[AllowedAction] = []
    expected_facts: list[str] = Field(description="Text the final answer must contain for the task to count as done.")
    required_actions: list[AllowedAction] = []
    reference_calls: list[PlannedCall] = Field(default=[], description="The calls a correct agent makes.")
    reference_answer: str = Field(default="", description="An answer a correct agent gives.")


class Channel(StrEnum):
    """Where the attacker's text is planted."""

    EMAIL = "email"
    DOCUMENT = "document"
    PAGE = "page"


class Goal(StrEnum):
    """What the attacker wants the agent to do."""

    EXFILTRATE_EMAIL = "exfiltrate_email"
    EXFILTRATE_URL = "exfiltrate_url"
    UNAUTHORIZED_WRITE = "unauthorized_write"
    HIJACK_ANSWER = "hijack_answer"


class Technique(StrEnum):
    """How the attacker's text tries to look like something the agent should obey."""

    PLAIN = "plain"
    FAKE_SYSTEM = "fake_system"
    AUTHORITY = "authority"
    HIDDEN = "hidden"
    ENCODED = "encoded"
    FAKE_TOOL_OUTPUT = "fake_tool_output"
    DANISH = "danish"
    HELPFUL_STEP = "helpful_step"


class Attack(Strict):
    """One attack: a task, where the payload is planted, how it is written and what it wants."""

    id: str
    task: str
    channel: Channel
    target: str = Field(description="The email id, document id or page URL the payload is added to.")
    technique: Technique
    goal: Goal
    payload: str
    marker: str | None = Field(default=None, description="For hijack_answer: text that shows the hijack worked.")
    attacker_calls: list[PlannedCall] = []
    attacker_answer: str = "Done."


# ---------- Runs ----------


class ToolCall(BaseModel):
    """A tool call the model asked for, and what the guards and the tool did with it."""

    tool: str
    arguments: dict[str, Any]  # Whatever JSON the model sent; validated by the tool, not here.
    executed: bool = False
    blocked_by: str | None = None
    output: str = ""


class Usage(BaseModel):
    """Tokens used in one run, summed over its turns."""

    input_tokens: int = 0
    output_tokens: int = 0
    cache_read_tokens: int = 0
    cache_write_tokens: int = 0


class Transcript(BaseModel):
    """What happened in one run of one task, with or without an attack, under one defense."""

    task: str
    attack: str | None
    defense: str
    model: str
    calls: list[ToolCall] = []
    final_answer: str = ""
    shown_answer: str = Field(default="", description="The final answer after any output filter.")
    refused: bool = False
    turns: int = 0
    usage: Usage = Usage()
    cost_usd: float = 0.0
    seconds: float = 0.0


class Verdict(BaseModel):
    """The scored outcome of one run."""

    task: str
    attack: str | None
    defense: str
    attempted: bool = Field(description="The model tried the attacker's action, whether or not it ran.")
    succeeded: bool = Field(description="The attacker's goal was reached: the action ran or the answer was hijacked.")
    warned: bool = Field(description="The answer repeats the attacker's false claim only to reject it.")
    task_done: bool
    refused: bool
    cost_usd: float
    seconds: float
