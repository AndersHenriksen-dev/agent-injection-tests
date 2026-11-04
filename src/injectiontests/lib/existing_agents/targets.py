"""Reading a skill or agent from another repo: its instructions, its tools and what those tools let it do.

The formats are Claude Code's Markdown files: `SKILL.md`, `.claude/commands/*.md` and `.claude/agents/*.md`. An agent
built on the API can be described the same way: a Markdown file with its tool names in the frontmatter and its system
prompt as the body.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from injectiontests.lib.shared.models import Capability, Strict, Target, TargetKind
from injectiontests.lib.shared.settings import config_for


class _TargetsConfig(Strict):
    default_tools: tuple[str, ...]
    skipped_folders: frozenset[str]
    tool_capabilities: dict[str, frozenset[Capability]]
    web_words: frozenset[str]
    read_words: frozenset[str]
    write_words: frozenset[str]


_CONFIG = config_for(__name__, _TargetsConfig)
DEFAULT_TOOLS = _CONFIG.default_tools

_FRONTMATTER = re.compile(r"\A---[ \t]*\r?\n(.*?)\r?\n---[ \t]*(?:\r?\n|\Z)(.*)\Z", re.DOTALL)
_SIMPLE_FIELD = re.compile(r"^([A-Za-z-]+):[ \t]*(.*)$", re.MULTILINE)
# A tool name with an optional pattern, in a comma- or space-separated string: "Read, Bash(git add *) Grep".
_TOOL_ENTRY = re.compile(r"[^\s,()]+(?:\([^)]*\))?")
_WORD = re.compile(r"[A-Z]?[a-z]+|[A-Z]+(?![a-z])")

# Where the words in a tool's name place it.
_READING = frozenset({Capability.READS_OUTSIDE_TEXT, Capability.READS_PRIVATE_DATA})
_WEB = frozenset({Capability.READS_OUTSIDE_TEXT, Capability.SENDS_OUT})
_SENDING = frozenset({Capability.SENDS_OUT, Capability.CHANGES_THINGS})
_ALL_BUT_COMMANDS = _READING | _SENDING


def base_tool(entry: str) -> str:
    """The tool name in an entry such as `Bash(git add *)`."""
    return entry.split("(")[0].strip()


def capabilities_of(tool: str) -> frozenset[Capability]:
    """What a tool lets an agent do.

    MCP and custom tools are placed by the words in their names. One that cannot be placed counts as able to do
    everything but run commands, which reports a risk that may not be there rather than miss one that is.
    """
    name = base_tool(tool)
    if name in _CONFIG.tool_capabilities:
        return _CONFIG.tool_capabilities[name]
    words = {word.lower() for word in _WORD.findall(name)}
    if words & _CONFIG.web_words:
        return _WEB
    reads, writes = bool(words & _CONFIG.read_words), bool(words & _CONFIG.write_words)
    if reads != writes:
        return _READING if reads else _SENDING
    return _ALL_BUT_COMMANDS


def tools_with(target: Target, capability: Capability) -> list[str]:
    """The target's tools that have a capability."""
    return [tool for tool in target.tools if capability in capabilities_of(tool)]


def _split_frontmatter(text: str) -> tuple[dict[str, object], str]:
    """The frontmatter fields and the body of a Markdown file. A file without frontmatter is all body."""
    match = _FRONTMATTER.match(text)
    if match is None:
        return {}, text.strip()
    raw, body = match.groups()
    try:
        fields = yaml.safe_load(raw)
    except yaml.YAMLError:
        # Claude Code accepts unquoted values such as "description: Use this: it helps", which are not valid YAML.
        fields = dict(_SIMPLE_FIELD.findall(raw))
    return (fields if isinstance(fields, dict) else {}), body.strip()


def _tool_entries(value: object) -> list[str]:
    """The entries of a tool field, written as a comma- or space-separated string or as a YAML list."""
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    return _TOOL_ENTRY.findall(str(value)) if value else []


def _is_skill(path: Path) -> bool:
    return path.name == "SKILL.md" or "commands" in path.parent.parts


def _name_of(path: Path) -> str:
    return path.parent.name if path.name == "SKILL.md" else path.stem


def load_target(path: Path) -> Target:
    """Read one skill or agent file.

    Raises:
        ValueError: The file has no instructions to test.
    """
    fields, body = _split_frontmatter(path.read_text(encoding="utf-8"))
    if not body:
        raise ValueError(f"{path} has no instructions after its frontmatter.")
    is_skill = _is_skill(path)
    # A subagent's `tools` is an allowlist. A skill's `allowed-tools` only pre-approves: every tool stays callable.
    listed = _tool_entries(fields.get("tools")) if not is_skill else []
    removed = {
        base_tool(entry) for entry in _tool_entries(fields.get("disallowed-tools" if is_skill else "disallowedTools"))
    }
    tools = listed or list(DEFAULT_TOOLS)
    model = fields.get("model")
    mode = fields.get("permissionMode")
    return Target(
        name=str(fields.get("name") or _name_of(path)),
        kind=TargetKind.SKILL if is_skill else TargetKind.SUBAGENT,
        path=path.as_posix(),
        description=str(fields.get("description") or ""),
        instructions=body,
        tools=[tool for tool in tools if base_tool(tool) not in removed],
        tools_listed=bool(listed),
        preapproved=_tool_entries(fields.get("allowed-tools")) if is_skill else [],
        permission_mode=str(mode) if mode else None,
        model=str(model) if model else None,
        model_invocable=fields.get("disable-model-invocation") is not True,
    )


def _is_target_file(file: Path) -> bool:
    """Whether a Markdown file is a skill, command or agent, and not a document that sits in a similar folder."""
    if file.name == "SKILL.md":
        return True
    parts = file.resolve().parent.parts
    if not {"agents", "commands"} & set(parts) or file.name.lower() == "readme.md":
        return False
    # Outside .claude, as in a plugin, only frontmatter tells an agent from a document in a folder named `agents`.
    return ".claude" in parts or file.read_text(encoding="utf-8", errors="ignore").startswith("---")


def find_target_files(path: Path) -> list[Path]:
    """The file itself, or every skill, command and agent file under a folder."""
    if path.is_file():
        return [path]
    return sorted(
        file for file in path.rglob("*.md") if not _CONFIG.skipped_folders & set(file.parts) and _is_target_file(file)
    )
