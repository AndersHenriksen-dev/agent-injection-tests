"""Command line: test a skill or agent from another repo, or run this repo's own eval.

`run`, `eval` and `scan` call the paid API, so `eval` and `scan` only print their plan unless given `--yes`.
"""

from __future__ import annotations

import argparse
import sys
from datetime import UTC, datetime
from pathlib import Path

import anthropic
from dotenv import find_dotenv, load_dotenv

from injectiontests.agent import ClaudeModel
from injectiontests.audit import audit
from injectiontests.cases import Cases, load
from injectiontests.config import EVALS_DIR, PRICES, RESULTS_DIR, SCAN_RESULTS_DIR, effort_from_env, model_from_env
from injectiontests.defenses import DEFENSES, Defense
from injectiontests.evaluate import (
    Result,
    append_result,
    by_goal,
    plan,
    read_results,
    run_matrix,
    run_one,
    summarize,
    table,
    worst_case,
    worst_case_problems,
)
from injectiontests.models import Attack, Severity, Target, Verdict
from injectiontests.report import audit_report, scan_report
from injectiontests.scan import AttackResult, Outcome, default_task, estimate_cost_usd, findings_from, model_for, scan
from injectiontests.targets import find_target_files, load_target, reachable_attacks


def _claude() -> tuple[ClaudeModel, str]:
    """A Claude model from the environment, and a one-line description of it."""
    load_dotenv(find_dotenv(usecwd=True))
    name, effort = model_from_env(), effort_from_env()
    return ClaudeModel(anthropic.Anthropic(), name, effort), f"{name} at effort {effort}"


def _scan_model(name: str) -> ClaudeModel:
    """A Claude model for a scan, which may differ per target."""
    load_dotenv(find_dotenv(usecwd=True))
    return ClaudeModel(anthropic.Anthropic(), name, effort_from_env())


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
    return f"{table(summarize(verdicts), with_model_columns=True)}\n\n{by_goal(cases, verdicts)}"


def _write_results(description: str, stamp: str, verdicts: list[Verdict], text: str) -> None:
    total = sum(verdict.cost_usd for verdict in verdicts)
    EVALS_DIR.mkdir(exist_ok=True)
    (EVALS_DIR / "RESULTS.md").write_text(
        f"# Results\n\n{description}, {len(verdicts)} runs on {stamp[:8]}, USD {total:.2f} in total.\n\n{text}\n",
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
    if len(results) != len(list(plan(cases, list(DEFENSES.values()), cases.attacks, with_tasks=True))):
        print(f"{args.path} is not a complete matrix, so evals/RESULTS.md is unchanged.", file=sys.stderr)
        return 1
    _write_results(f"{results[0][0].model} at effort {effort_from_env()}", args.path.parent.name, verdicts, text)
    return 0


_WORST_CASE_INTRO = """# Worst case

Every attack run by a fully hijacked model, which makes exactly the tool calls the attacker wants, and every task run \
by a model that does the job right. No API is called, so this is what the guards guarantee on their own, whatever the \
model does. Regenerate with `uv run injectiontests worst-case --write`.
"""


def _targets_at(path: Path) -> list[Target]:
    return [load_target(file) for file in find_target_files(path)]


def cmd_audit(_: Cases, args: argparse.Namespace) -> int:
    """Print what to fix in each skill or agent, for free. With --check, fail on anything high."""
    targets = _targets_at(args.path)
    if not targets:
        print(f"No skill or agent files found at {args.path}.", file=sys.stderr)
        return 1
    found = [(target, audit(target)) for target in targets]
    print("\n".join(audit_report(target, findings) for target, findings in found))
    high = any(finding.severity is Severity.HIGH for _, findings in found for finding in findings)
    return 1 if args.check and high else 0


def _print_scan_plan(cases: Cases, targets: list[Target], args: argparse.Namespace) -> None:
    total_runs, total_cost = 0, 0.0
    for target in targets:
        model = model_for(target, args.model, model_from_env())
        runs = len(reachable_attacks(target, cases.agent_attacks))
        cost = estimate_cost_usd(model, runs)
        total_runs, total_cost = total_runs + runs, total_cost + cost
        price = f"about USD {cost:.2f}" if model in PRICES else "cost unknown"
        print(f"{target.name} ({target.kind}): {runs} attacks with {model}, {price}")
    print(
        f"\nIn total {total_runs} runs, about USD {total_cost:.2f}. Tools are simulated, so nothing real runs, but "
        "each agent's instructions go to the API. Run again with --yes to start.",
    )


def _scan_target(cases: Cases, target: Target, args: argparse.Namespace, stamp: str) -> tuple[bool, bool]:
    """Scan one target and write its report. Returns whether any attack got through, and whether the API stopped it."""
    name = model_for(target, args.model, model_from_env())
    task = args.task or default_task(target)
    folder = SCAN_RESULTS_DIR / stamp
    folder.mkdir(parents=True, exist_ok=True)
    safe_name = "".join(character if character.isalnum() or character in "-_" else "-" for character in target.name)
    results: list[AttackResult] = []

    def on_result(result: AttackResult) -> None:
        results.append(result)
        with (folder / f"{safe_name}.jsonl").open("a", encoding="utf-8") as file:
            file.write(result.transcript.model_dump_json() + "\n")
        print(f"{target.name:<24} {result.attack.id:<34} {result.outcome}  ${result.transcript.cost_usd:.4f}")

    stopped = False
    try:
        scan(_scan_model(name), target, cases.agent_attacks, task, on_result)
    except (anthropic.APIStatusError, anthropic.APIConnectionError) as error:
        stopped = True
        print(f"\nStopped {target.name} after {len(results)} runs: {error}", file=sys.stderr)
    report = scan_report(target, [*findings_from(results), *audit(target)], results, name, task)
    path = folder / f"{safe_name}.md"
    path.write_text(report, encoding="utf-8", newline="\n")
    print(f"\n{report}\nReport in {path}")
    return any(result.outcome is Outcome.GOT_THROUGH for result in results), stopped


def cmd_scan(cases: Cases, args: argparse.Namespace) -> int:
    """Run planted attacks on each skill or agent with simulated tools. Without --yes, only print the plan."""
    targets = _targets_at(args.path)
    if not targets:
        print(f"No skill or agent files found at {args.path}.", file=sys.stderr)
        return 1
    if not args.yes:
        _print_scan_plan(cases, targets, args)
        return 0
    stamp = datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
    outcomes = [_scan_target(cases, target, args, stamp) for target in targets]
    return 1 if any(through or stopped for through, stopped in outcomes) else 0


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
    again = commands.add_parser("rescore", help="score saved runs again with the current rules (free)")
    again.add_argument("path", type=Path, help="a runs.jsonl file from results/")
    again.add_argument("--write", action="store_true", help="write evals/RESULTS.md from a complete matrix")
    check = commands.add_parser("audit", help="list what to fix in a skill or agent you own (free)")
    check.add_argument("path", type=Path, help="a skill or agent file, or a folder to search")
    check.add_argument("--check", action="store_true", help="exit 1 if anything is high severity")
    attack = commands.add_parser("scan", help="run planted attacks on a skill or agent you own (paid, tools simulated)")
    attack.add_argument("path", type=Path, help="a skill or agent file, or a folder to search")
    attack.add_argument("--task", help="a normal request for the agent, so that it reads something")
    attack.add_argument("--model", help="the model to test, instead of the one the file names")
    attack.add_argument("--yes", action="store_true", help="start the paid runs")
    args = parser.parse_args()
    handlers = {
        "list": cmd_list,
        "worst-case": cmd_worst_case,
        "run": cmd_run,
        "eval": cmd_eval,
        "rescore": cmd_rescore,
        "audit": cmd_audit,
        "scan": cmd_scan,
    }
    sys.exit(handlers[args.command](load(), args))
