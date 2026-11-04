"""Reading skills and agents from other repos: their fields, their tools and what those tools can do."""

from __future__ import annotations

from pathlib import Path

import pytest

from injectiontests.lib.existing_agents.attacks import load_attacks, reachable_attacks
from injectiontests.lib.existing_agents.targets import DEFAULT_TOOLS, capabilities_of, find_target_files, load_target
from injectiontests.lib.shared.models import AgentGoal, Capability, TargetKind

ATTACKS = load_attacks()


def _write(folder: Path, name: str, text: str) -> Path:
    path = folder / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", newline="\n")
    return path


class TestSubagent:
    @pytest.mark.parametrize("tools", ["tools: Read, Grep", "tools:\n  - Read\n  - Grep"])
    def test_tools_limit_it_in_either_form(self, tmp_path: Path, tools: str) -> None:
        target = load_target(_write(tmp_path, "reviewer.md", f"---\nname: reviewer\n{tools}\n---\nReview it."))
        assert target.kind is TargetKind.SUBAGENT
        assert target.tools == ["Read", "Grep"]
        assert target.tools_listed

    def test_without_tools_it_inherits_them(self, tmp_path: Path) -> None:
        target = load_target(_write(tmp_path, "reviewer.md", "---\nname: reviewer\n---\nReview it."))
        assert target.tools == list(DEFAULT_TOOLS)
        assert not target.tools_listed

    def test_disallowed_tools_are_removed(self, tmp_path: Path) -> None:
        text = "---\nname: reviewer\ndisallowedTools: Write, Edit\n---\nReview it."
        target = load_target(_write(tmp_path, "reviewer.md", text))
        assert "Write" not in target.tools
        assert "Read" in target.tools

    def test_fields_are_read(self, tmp_path: Path) -> None:
        text = "---\nname: r\ndescription: Reviews.\nmodel: haiku\npermissionMode: acceptEdits\n---\n\nReview it.\n"
        target = load_target(_write(tmp_path, "a.md", text))
        assert (target.name, target.description, target.model) == ("r", "Reviews.", "haiku")
        assert target.permission_mode == "acceptEdits"
        assert target.instructions == "Review it."


class TestSkill:
    def test_allowed_tools_only_pre_approve(self, tmp_path: Path) -> None:
        text = "---\nname: s\nallowed-tools: Read\n---\nDo it."
        target = load_target(_write(tmp_path, "s/SKILL.md", text))
        assert target.kind is TargetKind.SKILL
        assert target.preapproved == ["Read"]
        assert target.tools == list(DEFAULT_TOOLS)
        assert not target.tools_listed

    def test_allowed_tools_with_patterns_separated_by_spaces(self, tmp_path: Path) -> None:
        text = "---\nname: s\nallowed-tools: Bash(git add *) Bash(git commit *) Read\n---\nDo it."
        target = load_target(_write(tmp_path, "s/SKILL.md", text))
        assert target.preapproved == ["Bash(git add *)", "Bash(git commit *)", "Read"]

    def test_disallowed_tools_are_what_limits_it(self, tmp_path: Path) -> None:
        text = "---\nname: s\ndisallowed-tools: Bash(git push *), WebFetch\n---\nDo it."
        target = load_target(_write(tmp_path, "s/SKILL.md", text))
        assert "Bash" not in target.tools
        assert "WebFetch" not in target.tools

    def test_name_comes_from_the_folder(self, tmp_path: Path) -> None:
        assert load_target(_write(tmp_path, "my-skill/SKILL.md", "Do it.")).name == "my-skill"

    def test_a_command_without_frontmatter_is_a_skill(self, tmp_path: Path) -> None:
        target = load_target(_write(tmp_path, ".claude/commands/ship.md", "Ship it."))
        assert (target.kind, target.name, target.instructions) == (TargetKind.SKILL, "ship", "Ship it.")

    def test_it_can_be_kept_from_starting_on_its_own(self, tmp_path: Path) -> None:
        text = "---\nname: s\ndisable-model-invocation: true\n---\nDo it."
        assert not load_target(_write(tmp_path, "s/SKILL.md", text)).model_invocable
        assert load_target(_write(tmp_path, "t/SKILL.md", "Do it.")).model_invocable


class TestBadFiles:
    def test_an_unquoted_colon_is_not_an_error(self, tmp_path: Path) -> None:
        text = "---\nname: s\ndescription: Use this: it helps\ntools: Read\n---\nDo it."
        target = load_target(_write(tmp_path, "a.md", text))
        assert target.description == "Use this: it helps"
        assert target.tools == ["Read"]

    def test_no_instructions_is_an_error(self, tmp_path: Path) -> None:
        with pytest.raises(ValueError, match="no instructions"):
            load_target(_write(tmp_path, "a.md", "---\nname: s\n---\n"))


class TestCapabilities:
    @pytest.mark.parametrize(
        ("tool", "has", "lacks"),
        [
            ("Read", Capability.READS_PRIVATE_DATA, Capability.SENDS_OUT),
            ("Bash(git add *)", Capability.RUNS_COMMANDS, None),
            ("WebFetch", Capability.SENDS_OUT, Capability.CHANGES_THINGS),
            ("Write", Capability.CHANGES_THINGS, Capability.SENDS_OUT),
            ("mcp__github__get_issue", Capability.READS_OUTSIDE_TEXT, Capability.SENDS_OUT),
            ("mcp__slack__post_message", Capability.SENDS_OUT, Capability.READS_PRIVATE_DATA),
            ("sendRefund", Capability.SENDS_OUT, Capability.READS_OUTSIDE_TEXT),
            ("mcp__fetch__fetch", Capability.SENDS_OUT, Capability.CHANGES_THINGS),
        ],
    )
    def test_known_and_named_tools(self, tool: str, has: Capability, lacks: Capability | None) -> None:
        assert has in capabilities_of(tool)
        if lacks:
            assert lacks not in capabilities_of(tool)

    def test_a_tool_it_cannot_place_counts_as_risky(self) -> None:
        assert Capability.SENDS_OUT in capabilities_of("mcp__acme__frobnicate")
        assert Capability.RUNS_COMMANDS not in capabilities_of("mcp__acme__frobnicate")

    def test_harmless_tools_do_nothing(self) -> None:
        assert capabilities_of("TodoWrite") == frozenset()


class TestFindingFiles:
    def test_a_file_is_itself(self, tmp_path: Path) -> None:
        path = _write(tmp_path, "anything.md", "Do it.")
        assert find_target_files(path) == [path]

    def test_a_folder_finds_skills_commands_and_agents_only(self, tmp_path: Path) -> None:
        found = {
            _write(tmp_path, name, text)
            for name, text in [
                (".claude/agents/a.md", "No frontmatter."),
                (".claude/agents/nested/b.md", "No frontmatter."),
                (".claude/commands/c.md", "No frontmatter."),
                (".claude/skills/d/SKILL.md", "No frontmatter."),
                ("plugin/agents/e.md", "---\nname: e\n---\nDo it."),
            ]
        }
        for name in [
            "README.md",
            ".claude/agents/README.md",
            "docs/agents/guide.md",
            ".venv/lib/x/SKILL.md",
            "docs/notes.md",
        ]:
            _write(tmp_path, name, "A document.")
        assert set(find_target_files(tmp_path)) == found

    def test_pointing_at_the_agents_folder_works(self, tmp_path: Path) -> None:
        path = _write(tmp_path, ".claude/agents/a.md", "Do it.")
        assert find_target_files(tmp_path / ".claude" / "agents") == [path]


class TestReach:
    def test_goals_follow_the_tools(self, tmp_path: Path) -> None:
        target = load_target(_write(tmp_path, "a.md", "---\nname: a\ntools: Read\n---\nDo it."))
        goals = {attack.goal for attack in reachable_attacks(target, ATTACKS)}
        assert goals == {AgentGoal.LEAK_SECRET, AgentGoal.HIJACK_ANSWER}

    def test_a_shell_reaches_every_goal(self, tmp_path: Path) -> None:
        target = load_target(_write(tmp_path, "a.md", "---\nname: a\ntools: Bash\n---\nDo it."))
        assert len(reachable_attacks(target, ATTACKS)) == len(ATTACKS)

    def test_without_a_way_in_nothing_is_reachable(self, tmp_path: Path) -> None:
        target = load_target(_write(tmp_path, "a.md", "---\nname: a\ntools: Write\n---\nDo it."))
        assert reachable_attacks(target, ATTACKS) == []
