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


class ToolSpec(Strict):
    """A tool as a config file describes it: what it does, and each parameter with its description."""

    description: str
    parameters: dict[str, str]


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
    expected_facts: list[str] = Field(description="Patterns the final answer must match for the task to be done.")
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
    PLAUSIBLE_DATA = "plausible_data"


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


# ---------- Skills and agents from other repos ----------


class Capability(StrEnum):
    """What a tool lets an agent do, which decides what an attacker could reach through it."""

    READS_OUTSIDE_TEXT = "reads_outside_text"
    READS_PRIVATE_DATA = "reads_private_data"
    SENDS_OUT = "sends_out"
    CHANGES_THINGS = "changes_things"
    RUNS_COMMANDS = "runs_commands"


class TargetKind(StrEnum):
    """Which Claude Code format a target is written in. The two limit tools differently."""

    SKILL = "skill"
    SUBAGENT = "subagent"


class Target(Strict):
    """A skill or agent from another repo, as read from its Markdown file."""

    name: str
    kind: TargetKind
    path: str
    description: str = ""
    instructions: str
    tools: list[str] = Field(description="Everything it can call, after any limits in its file.")
    tools_listed: bool = Field(description="Whether its file limits its tools. A skill's `allowed-tools` does not.")
    preapproved: list[str] = Field(default=[], description="What a skill's `allowed-tools` runs without asking.")
    permission_mode: str | None = None
    model: str | None = None
    model_invocable: bool = True


class AgentGoal(StrEnum):
    """What an attacker wants from a skill or agent, whatever its job is."""

    EXFILTRATE = "exfiltrate"
    RUN_COMMAND = "run_command"
    CHANGE_FILES = "change_files"
    LEAK_SECRET = "leak_secret"
    HIJACK_ANSWER = "hijack_answer"


class AgentAttack(Strict):
    """One attack on any skill or agent: text planted in the first thing it reads, and how to tell that it worked."""

    id: str
    technique: Technique
    goal: AgentGoal
    payload: str
    needs: Capability | None = Field(default=None, description="The capability the goal takes. None: any target.")
    call_marker: str | None = Field(default=None, description="Text in a tool call that shows the attack worked.")
    answer_marker: str | None = Field(default=None, description="Text stated in the answer that shows it worked.")
    attacker_call: PlannedCall | None = Field(default=None, description="The call a fully hijacked model makes.")
    attacker_answer: str = "Done."


class Severity(StrEnum):
    """How urgent a finding is. High means nothing stands between the attacker and the harm."""

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class Finding(Strict):
    """One thing to fix in a skill or agent."""

    severity: Severity
    title: str
    why: str
    fix: str


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
    pass_number: int = Field(default=1, description="Which pass over the matrix this run belongs to.")


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
    pass_number: int = 1
