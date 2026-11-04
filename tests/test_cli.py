"""The paid eval command: its plan, saving as it goes, and what it does when the API stops it."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import anthropic
import httpx2
import pytest
from anthropic.types import Message, MessageParam, ToolParam

from injectiontests import cli
from injectiontests.agent import ScriptedModel
from injectiontests.cases import Cases


class FailsAfter:
    """A model that answers a number of turns, then fails the way the API does."""

    name = "fails-after"

    def __init__(self, turns: int) -> None:
        """Answer `turns` turns before failing."""
        self.turns = turns

    def respond(self, *, system: str, tools: list[ToolParam], messages: list[MessageParam]) -> Message:
        if self.turns == 0:
            raise anthropic.APIConnectionError(request=httpx2.Request("POST", "https://api.anthropic.test/v1/messages"))
        self.turns -= 1
        return ScriptedModel([], "ok").respond(system=system, tools=tools, messages=messages)


def _args(**overrides: object) -> argparse.Namespace:
    values: dict[str, object] = {"defense": None, "attack": None, "no_tasks": False, "yes": True}
    return argparse.Namespace(**{**values, **overrides})


def _use(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, model: object) -> None:
    monkeypatch.setattr(cli, "_claude", lambda: (model, "test model"))
    monkeypatch.setattr(cli, "RESULTS_DIR", tmp_path / "results")
    monkeypatch.setattr(cli, "EVALS_DIR", tmp_path)


def _saved(tmp_path: Path) -> list[dict[str, object]]:
    files = list((tmp_path / "results").glob("*/runs.jsonl"))
    assert len(files) == 1
    return [json.loads(line) for line in files[0].read_text(encoding="utf-8").splitlines()]


class TestEval:
    def test_without_yes_it_only_prints_the_plan(
        self,
        cases: Cases,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        _use(monkeypatch, tmp_path, FailsAfter(0))
        assert cli.cmd_eval(cases, _args(yes=False)) == 0
        assert "203 runs" in capsys.readouterr().out
        assert not (tmp_path / "results").exists()

    def test_an_api_error_keeps_the_runs_already_paid_for(
        self,
        cases: Cases,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        _use(monkeypatch, tmp_path, FailsAfter(3))
        assert cli.cmd_eval(cases, _args()) == 1
        assert len(_saved(tmp_path)) == 3
        assert not (tmp_path / "RESULTS.md").exists()

    def test_a_filtered_run_does_not_replace_the_results(
        self,
        cases: Cases,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        _use(monkeypatch, tmp_path, ScriptedModel([], "ok"))
        assert cli.cmd_eval(cases, _args(defense=["none"], no_tasks=True)) == 0
        assert len(_saved(tmp_path)) == len(cases.attacks)
        assert not (tmp_path / "RESULTS.md").exists()

    def test_a_complete_matrix_writes_the_results_with_its_cost(
        self,
        cases: Cases,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        _use(monkeypatch, tmp_path, ScriptedModel([], "ok"))
        assert cli.cmd_eval(cases, _args()) == 0
        assert len(_saved(tmp_path)) == 203
        results = (tmp_path / "RESULTS.md").read_text(encoding="utf-8")
        assert "test model, 203 runs" in results
        assert "USD 0.00 in total" in results
