"""Command line: list the cases, run the free worst-case check, or run attacks against Claude.

`run` and `eval` call the paid API, so `eval` only prints its plan unless it is given `--yes`.
"""

from __future__ import annotations

import argparse
import sys
from datetime import UTC, datetime

import anthropic
from dotenv import load_dotenv

from injectiontests.agent import ClaudeModel
from injectiontests.cases import Cases, load
from injectiontests.config import EVALS_DIR, RESULTS_DIR, effort_from_env, model_from_env
from injectiontests.defenses import DEFENSES, Defense
from injectiontests.evaluate import (
    Result,
    append_result,
    by_goal,
    plan,
    run_matrix,
    run_one,
    summarize,
    table,
    worst_case,
    worst_case_problems,
)
from injectiontests.models import Attack


def _claude() -> tuple[ClaudeModel, str]:
    """A Claude model from the environment, and a one-line description of it."""
    load_dotenv()
    name, effort = model_from_env(), effort_from_env()
    return ClaudeModel(anthropic.Anthropic(), name, effort), f"{name} at effort {effort}"


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

    Each run is saved as soon as it finishes, so an API error such as a spend limit loses nothing already paid for.
    Only a complete, unfiltered matrix replaces evals/RESULTS.md.
    """
    defenses, attacks = _defenses(args.defense), _attacks(cases, args.attack)
    runs = len(list(plan(cases, defenses, attacks, not args.no_tasks)))
    if not args.yes:
        print(f"{runs} runs against {model_from_env()} at effort {effort_from_env()}. Run again with --yes to start.")
        return 0
    model, description = _claude()
    stamp = datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
    path = RESULTS_DIR / stamp / "runs.jsonl"
    results: list[Result] = []

    def on_result(result: Result) -> None:
        results.append(result)
        append_result(result, path)
        _print_result(result)

    stopped = False
    try:
        run_matrix(model, cases, defenses, attacks, not args.no_tasks, on_result)
    except (anthropic.APIStatusError, anthropic.APIConnectionError) as error:
        stopped = True
        print(f"\nStopped after {len(results)} of {runs} runs: {error}", file=sys.stderr)

    verdicts = [verdict for _, verdict in results]
    total = sum(verdict.cost_usd for verdict in verdicts)
    text = f"{table(summarize(verdicts), with_model_columns=True)}\n\n{by_goal(cases, verdicts)}"
    if not (stopped or args.defense or args.attack or args.no_tasks):
        (EVALS_DIR / "RESULTS.md").write_text(
            f"# Results\n\n{description}, {runs} runs on {stamp[:8]}, USD {total:.2f} in total.\n\n{text}\n",
            encoding="utf-8",
            newline="\n",
        )
    print(f"\n{text}\n\nUSD {total:.4f} in total. Transcripts in {path}")
    return 1 if stopped else 0


_WORST_CASE_INTRO = """# Worst case

Every attack run by a fully hijacked model, which makes exactly the tool calls the attacker wants, and every task run \
by a model that does the job right. No API is called, so this is what the guards guarantee on their own, whatever the \
model does. Regenerate with `uv run injectiontests worst-case --write`.
"""


def main() -> None:
    """Parse the command line and run a command."""
    parser = argparse.ArgumentParser(prog="injectiontests", description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("list", help="list tasks, attacks and defenses")
    worst = commands.add_parser("worst-case", help="run every case with scripted models (free)")
    worst.add_argument("--check", action="store_true", help="exit 1 if a guard guarantee breaks")
    worst.add_argument("--write", action="store_true", help="write evals/WORST_CASE.md")
    one = commands.add_parser("run", help="run one task or attack against Claude (paid)")
    one.add_argument("--task", default="summarize_inbox")
    one.add_argument("--attack")
    one.add_argument("--defense", default="none", choices=list(DEFENSES))
    matrix = commands.add_parser("eval", help="run the matrix against Claude (paid)")
    matrix.add_argument("--defense", nargs="*", choices=list(DEFENSES))
    matrix.add_argument("--attack", nargs="*")
    matrix.add_argument("--no-tasks", action="store_true", help="skip the runs without an attack")
    matrix.add_argument("--yes", action="store_true", help="start the paid runs")
    args = parser.parse_args()
    handlers = {"list": cmd_list, "worst-case": cmd_worst_case, "run": cmd_run, "eval": cmd_eval}
    sys.exit(handlers[args.command](load(), args))
