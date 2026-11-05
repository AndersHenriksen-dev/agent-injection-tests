"""The paid eval command: its plan, saving as it goes, what it does when the API stops it, and rescoring its runs."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import anthropic
import httpx2
import pytest
from anthropic.types import Message, MessageParam, ToolParam

from injectiontests.lib.fund_agent import commands
from injectiontests.lib.fund_agent.cases import Cases
from injectiontests.lib.fund_agent.evaluate import read_results
from injectiontests.lib.shared.loop import ScriptedModel


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
    values: dict[str, object] = {
        "defense": None,
        "attack": None,
        "no_tasks": False,
        "yes": True,
        "passes": 1,
        "resume": None,
    }
    return argparse.Namespace(**{**values, **overrides})


def _use(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, model: object) -> None:
    monkeypatch.setattr(commands, "_claude", lambda: (model, "test model"))
    monkeypatch.setattr(commands, "RESULTS_DIR", tmp_path / "results")
    monkeypatch.setattr(commands, "EVALS_DIR", tmp_path)


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
        assert commands.cmd_eval(cases, _args(yes=False)) == 0
        assert "266 runs" in capsys.readouterr().out
        assert not (tmp_path / "results").exists()

    def test_an_api_error_keeps_the_runs_already_paid_for(
        self,
        cases: Cases,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        monkeypatch.setattr("injectiontests.lib.fund_agent.evaluate._CONFIG.parallel_runs", 1)
        _use(monkeypatch, tmp_path, FailsAfter(3))
        assert commands.cmd_eval(cases, _args()) == 1
        assert len(_saved(tmp_path)) == 3
        assert not (tmp_path / "RESULTS.md").exists()

    def test_a_filtered_run_does_not_replace_the_results(
        self,
        cases: Cases,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        _use(monkeypatch, tmp_path, ScriptedModel([], "ok"))
        assert commands.cmd_eval(cases, _args(defense=["none"], no_tasks=True)) == 0
        assert len(_saved(tmp_path)) == len(cases.attacks)
        assert not (tmp_path / "RESULTS.md").exists()

    def test_a_complete_matrix_writes_the_results_with_its_cost(
        self,
        cases: Cases,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        _use(monkeypatch, tmp_path, ScriptedModel([], "ok"))
        assert commands.cmd_eval(cases, _args()) == 0
        assert len(_saved(tmp_path)) == 266
        results = (tmp_path / "RESULTS.md").read_text(encoding="utf-8")
        assert "test model, 266 runs" in results
        assert "USD 0.00 in total" in results


class TestResults:
    def test_the_table_names_the_warnings_it_excused(
        self,
        cases: Cases,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        _use(monkeypatch, tmp_path, ScriptedModel([], "ok"))
        assert commands.cmd_eval(cases, _args()) == 0
        assert "Claims quoted and rejected or doubted" in (tmp_path / "RESULTS.md").read_text(encoding="utf-8")


class TestResume:
    def test_it_finishes_a_stopped_run_without_repeating_what_was_saved(
        self,
        cases: Cases,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        monkeypatch.setattr("injectiontests.lib.fund_agent.evaluate._CONFIG.parallel_runs", 1)
        _use(monkeypatch, tmp_path, FailsAfter(3))
        assert commands.cmd_eval(cases, _args()) == 1
        path = next((tmp_path / "results").glob("*/runs.jsonl"))

        calls: list[str] = []

        class Counts(ScriptedModel):
            def respond(self, *, system: str, tools: list[ToolParam], messages: list[MessageParam]) -> Message:
                calls.append(system)
                return super().respond(system=system, tools=tools, messages=messages)

        _use(monkeypatch, tmp_path, Counts([], "ok"))
        assert commands.cmd_eval(cases, _args(resume=path)) == 0
        assert len(calls) == 263
        rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
        runs = [(r["transcript"]["task"], r["transcript"]["attack"], r["transcript"]["defense"]) for r in rows]
        assert len(runs) == 266
        assert len(set(runs)) == 266
        assert "266 runs" in (tmp_path / "RESULTS.md").read_text(encoding="utf-8")


class TestPasses:
    def test_each_pass_is_kept_and_counted(
        self,
        cases: Cases,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        _use(monkeypatch, tmp_path, ScriptedModel([], "ok"))
        assert commands.cmd_eval(cases, _args(passes=2)) == 0
        assert len(_saved(tmp_path)) == 532
        results = (tmp_path / "RESULTS.md").read_text(encoding="utf-8")
        assert "532 runs in 2 passes" in results
        assert "Got through in each pass" in results
        assert "0, 0" in results

    def test_one_pass_shows_no_spread(
        self,
        cases: Cases,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        _use(monkeypatch, tmp_path, ScriptedModel([], "ok"))
        assert commands.cmd_eval(cases, _args()) == 0
        assert "Got through in each pass" not in (tmp_path / "RESULTS.md").read_text(encoding="utf-8")

    def test_the_results_compare_techniques(
        self,
        cases: Cases,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        _use(monkeypatch, tmp_path, ScriptedModel([], "ok"))
        assert commands.cmd_eval(cases, _args()) == 0
        assert "| plausible_data | 0 of 7 |" in (tmp_path / "RESULTS.md").read_text(encoding="utf-8")

    def test_rescoring_two_passes_counts_as_complete(
        self,
        cases: Cases,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        _use(monkeypatch, tmp_path, ScriptedModel([], "ok"))
        commands.cmd_eval(cases, _args(passes=2))
        path = next((tmp_path / "results").glob("*/runs.jsonl"))
        assert commands.cmd_rescore(cases, argparse.Namespace(path=path, write=True)) == 0


class TestRescore:
    def _saved_path(
        self,
        cases: Cases,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
        **eval_args: object,
    ) -> Path:
        _use(monkeypatch, tmp_path, ScriptedModel([], "ok"))
        commands.cmd_eval(cases, _args(**eval_args))
        return next((tmp_path / "results").glob("*/runs.jsonl"))

    def test_saved_verdicts_are_ignored(self, cases: Cases, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        path = self._saved_path(cases, monkeypatch, tmp_path, defense=["none"], no_tasks=True)
        rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
        rows[0]["verdict"]["succeeded"] = True
        path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8", newline="\n")
        results = read_results(path, cases)
        assert len(results) == len(cases.attacks)
        assert not results[0][1].succeeded

    def test_write_replaces_the_results_from_a_complete_matrix(
        self,
        cases: Cases,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        path = self._saved_path(cases, monkeypatch, tmp_path)
        monkeypatch.delenv("INJECTIONTESTS_EFFORT", raising=False)
        (tmp_path / "RESULTS.md").unlink()
        assert commands.cmd_rescore(cases, argparse.Namespace(path=path, write=True)) == 0
        results = (tmp_path / "RESULTS.md").read_text(encoding="utf-8")
        assert f"scripted at effort medium, 266 runs on {path.parent.name[:8]}" in results

    def test_without_write_it_only_prints(
        self,
        cases: Cases,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        path = self._saved_path(cases, monkeypatch, tmp_path, defense=["none"], no_tasks=True)
        capsys.readouterr()
        assert commands.cmd_rescore(cases, argparse.Namespace(path=path, write=False)) == 0
        assert "Attacks that got through" in capsys.readouterr().out
        assert not (tmp_path / "RESULTS.md").exists()

    def test_a_partial_file_does_not_replace_the_results(
        self,
        cases: Cases,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
    ) -> None:
        path = self._saved_path(cases, monkeypatch, tmp_path, defense=["none"], no_tasks=True)
        assert commands.cmd_rescore(cases, argparse.Namespace(path=path, write=True)) == 1
        assert not (tmp_path / "RESULTS.md").exists()
