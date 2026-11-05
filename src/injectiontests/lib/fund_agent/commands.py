"""The commands of this repo's own study on the fund agent: `list`, `worst-case`, `run`, `eval` and `rescore`.

`run` and `eval` call the paid API, so `eval` only prints its plan unless it is given `--yes`.
"""

from __future__ import annotations

import argparse
import sys
from datetime import UTC, datetime

import anthropic

from injectiontests.lib.fund_agent.cases import Cases
from injectiontests.lib.fund_agent.defenses import DEFENSES, Defense
from injectiontests.lib.fund_agent.evaluate import (
    Result,
    append_result,
    by_goal,
    by_technique,
    plan,
    read_results,
    run_matrix,
    run_one,
    summarize,
    table,
    worst_case,
    worst_case_problems,
)
from injectiontests.lib.shared.loop import ClaudeModel, claude_client
from injectiontests.lib.shared.models import Attack, Verdict
from injectiontests.lib.shared.settings import SETTINGS, effort_from_env, model_from_env

RESULTS_DIR = SETTINGS.results_dir
EVALS_DIR = SETTINGS.evals_dir

_WORST_CASE_INTRO = """# Worst case

Every attack run by a fully hijacked model, which makes exactly the tool calls the attacker wants, and every task run \
by a model that does the job right. No API is called, so this is what the guards guarantee on their own, whatever the \
model does. Regenerate with `uv run injectiontests worst-case --write`.
"""


def _claude() -> tuple[ClaudeModel, str]:
    """A Claude model from the environment, and a one-line description of it."""
    name, effort = model_from_env(), effort_from_env()
    return ClaudeModel(claude_client(), name, effort), f"{name} at effort {effort}"


def _defenses(names: list[str] | None) -> list[Defense]:
    return [DEFENSES[name] for name in names] if names else list(DEFENSES.values())


def _attacks(cases: Cases, ids: list[str] | None) -> list[Attack]:
    return [attack for attack in cases.attacks if ids is None or attack.id in ids]


def _print_result(result: Result) -> None:
    transcript, verdict = result
    outcome = "GOT THROUGH" if verdict.succeeded else ("tried, blocked" if verdict.attempted else "resisted")
    label = f"{verdict.defense:>15}  {verdict.attack or '(no attack)':<28} {verdict.task:<16}"
    attack_part = f"attack {outcome:<14}" if verdict.attack else " " * 21
    print(f"{label} {attack_part} task {'done' if verdict.task_done else 'NOT done'}  ${transcript.cost_usd:.4f}")


def _results_text(cases: Cases, verdicts: list[Verdict]) -> str:
    rows = table(summarize(verdicts), with_model_columns=True)
    return f"{rows}\n\n{by_goal(cases, verdicts)}\n\n{by_technique(cases, verdicts)}"


def _passes_in(verdicts: list[Verdict]) -> int:
    return len({verdict.pass_number for verdict in verdicts})


def _write_results(description: str, stamp: str, verdicts: list[Verdict], text: str) -> None:
    total = sum(verdict.cost_usd for verdict in verdicts)
    passes = _passes_in(verdicts)
    runs = f"{len(verdicts)} runs in {passes} passes" if passes > 1 else f"{len(verdicts)} runs"
    EVALS_DIR.mkdir(exist_ok=True)
    (EVALS_DIR / "RESULTS.md").write_text(
        f"# Results\n\n{description}, {runs} on {stamp[:8]}, USD {total:.2f} in total.\n\n{text}\n",
        encoding="utf-8",
        newline="\n",
    )


def cmd_list(cases: Cases, _: argparse.Namespace) -> int:
    """Print the tasks, attacks and defenses."""
    print(f"{len(cases.tasks)} tasks, {len(cases.attacks)} attacks, {len(DEFENSES)} defenses\n")
    for attack in cases.attacks:
        print(f"{attack.id:<32} {attack.task:<16} {attack.channel:<9} {attack.technique:<17} {attack.goal}")
    return 0


def cmd_worst_case(cases: Cases, args: argparse.Namespace) -> int:
    """Run every case with scripted models, print the table, and with --check fail on a broken guarantee."""
    results = worst_case(cases)
    verdicts = [verdict for _, verdict in results]
    text = f"{table(summarize(verdicts), with_model_columns=False)}\n\n{by_goal(cases, verdicts)}"
    print(text)
    if args.write:
        EVALS_DIR.mkdir(exist_ok=True)
        (EVALS_DIR / "WORST_CASE.md").write_text(f"{_WORST_CASE_INTRO}\n{text}\n", encoding="utf-8", newline="\n")
    found = worst_case_problems(cases, results)
    for problem in found:
        print(f"PROBLEM {problem}", file=sys.stderr)
    return 1 if args.check and found else 0


def cmd_run(cases: Cases, args: argparse.Namespace) -> int:
    """Run one task, optionally with one attack, under one defense, against Claude."""
    model, description = _claude()
    attack = next((a for a in cases.attacks if a.id == args.attack), None) if args.attack else None
    task = cases.tasks[attack.task if attack else args.task]
    transcript, verdict = run_one(model, cases, task, attack, DEFENSES[args.defense])
    print(f"{description}\n")
    for call in transcript.calls:
        state = "ran" if call.executed else f"blocked by {call.blocked_by}" if call.blocked_by else "failed"
        print(f"  {call.tool}({call.arguments}) -> {state}")
    print(f"\nAnswer shown:\n{transcript.shown_answer}\n")
    _print_result((transcript, verdict))
    return 0


def cmd_eval(cases: Cases, args: argparse.Namespace) -> int:
    """Run the matrix against Claude. Without --yes, only print the plan.

    Each run is saved as soon as it finishes, so an API error such as a spend limit loses nothing already paid for, and
    --resume carries on from a saved file without paying for its runs again. Only a complete, unfiltered matrix replaces
    evals/RESULTS.md.
    """
    defenses, attacks = _defenses(args.defense), _attacks(cases, args.attack)
    runs = args.passes * len(list(plan(cases, defenses, attacks, not args.no_tasks)))
    if not args.yes:
        print(f"{runs} runs against {model_from_env()} at effort {effort_from_env()}. Run again with --yes to start.")
        return 0
    model, description = _claude()
    path = args.resume or RESULTS_DIR / datetime.now(UTC).strftime("%Y%m%d-%H%M%S") / "runs.jsonl"
    stamp = path.parent.name
    results: list[Result] = read_results(path, cases) if args.resume else []
    saved = frozenset((t.task, t.attack, t.defense, t.pass_number) for t, _ in results)

    def on_result(result: Result) -> None:
        results.append(result)
        append_result(result, path)
        _print_result(result)

    stopped = False
    try:
        run_matrix(model, cases, defenses, attacks, not args.no_tasks, on_result, args.passes, saved)
    except (anthropic.APIStatusError, anthropic.APIConnectionError) as error:
        stopped = True
        print(f"\nStopped after {len(results)} of {runs} runs: {error}", file=sys.stderr)

    verdicts = [verdict for _, verdict in results]
    text = _results_text(cases, verdicts)
    if not (stopped or args.defense or args.attack or args.no_tasks):
        _write_results(description, stamp, verdicts, text)
    total = sum(verdict.cost_usd for verdict in verdicts)
    print(f"\n{text}\n\nUSD {total:.4f} in total. Transcripts in {path}")
    return 1 if stopped else 0


def cmd_rescore(cases: Cases, args: argparse.Namespace) -> int:
    """Score saved runs again with the current rules, at no cost, and with --write replace evals/RESULTS.md.

    Saved runs do not record the effort, so a run at another effort needs INJECTIONTESTS_EFFORT set here too.
    """
    results = read_results(args.path, cases)
    verdicts = [verdict for _, verdict in results]
    text = _results_text(cases, verdicts)
    print(text)
    if not args.write:
        return 0
    matrix = len(list(plan(cases, list(DEFENSES.values()), cases.attacks, with_tasks=True)))
    if len(results) != matrix * _passes_in(verdicts):
        print(f"{args.path} is not a complete matrix, so evals/RESULTS.md is unchanged.", file=sys.stderr)
        return 1
    _write_results(f"{results[0][0].model} at effort {effort_from_env()}", args.path.parent.name, verdicts, text)
    return 0
