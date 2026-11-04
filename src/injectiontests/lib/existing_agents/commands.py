"""The commands that test a skill or agent you own: `audit`, which is free, and `scan`, which calls the API."""

from __future__ import annotations

import argparse
import sys
from datetime import UTC, datetime
from pathlib import Path

import anthropic

from injectiontests.lib.existing_agents.attacks import load_attacks, reachable_attacks
from injectiontests.lib.existing_agents.audit import audit
from injectiontests.lib.existing_agents.report import audit_report, scan_report
from injectiontests.lib.existing_agents.sandbox import EMULATOR_EFFORT, EMULATOR_MODEL, ToolEmulator
from injectiontests.lib.existing_agents.scan import (
    AttackResult,
    Outcome,
    default_task,
    estimate_cost_usd,
    findings_from,
    model_for,
    scan,
)
from injectiontests.lib.existing_agents.targets import find_target_files, load_target
from injectiontests.lib.shared.loop import ClaudeModel, claude_client
from injectiontests.lib.shared.models import Severity, Target
from injectiontests.lib.shared.settings import SETTINGS, effort_from_env, model_from_env

SCAN_RESULTS_DIR = SETTINGS.scan_results_dir

_NO_API_KEY = """No API key found. A scan calls the Anthropic API, so set ANTHROPIC_API_KEY or put it in a .env file \
in this folder. `injectiontests audit` needs no key."""


def _scan_model(name: str) -> ClaudeModel:
    """A Claude model for a scan, which may differ per target."""
    return ClaudeModel(claude_client(), name, effort_from_env())


def _emulator_model() -> ClaudeModel:
    """The small model that writes a scan's simulated tool output."""
    return ClaudeModel(claude_client(), EMULATOR_MODEL, EMULATOR_EFFORT, cache_conversation=False)


def _targets_at(path: Path) -> list[Target]:
    """Every skill or agent at a path. A file it cannot read is reported and skipped, so it cannot stop the rest."""
    targets: list[Target] = []
    for file in find_target_files(path):
        try:
            targets.append(load_target(file))
        except ValueError as error:
            print(f"Skipping {file}: {error}", file=sys.stderr)
    return targets


def cmd_audit(args: argparse.Namespace) -> int:
    """Print what to fix in each skill or agent, for free. With --check, fail on anything high."""
    targets = _targets_at(args.path)
    if not targets:
        print(f"No skill or agent files found at {args.path}.", file=sys.stderr)
        return 1
    found = [(target, audit(target)) for target in targets]
    print("\n".join(audit_report(target, findings) for target, findings in found))
    high = any(finding.severity is Severity.HIGH for _, findings in found for finding in findings)
    return 1 if args.check and high else 0


def _print_scan_plan(targets: list[Target], args: argparse.Namespace) -> None:
    attacks = load_attacks()
    total_runs, total_cost = 0, 0.0
    for target in targets:
        model = model_for(target, args.model, model_from_env())
        runs = len(reachable_attacks(target, attacks))
        cost = estimate_cost_usd(model, runs)
        total_runs, total_cost = total_runs + runs, total_cost + cost
        price = f"about USD {cost:.2f}" if model in SETTINGS.prices else "cost unknown"
        print(f"{target.name} ({target.kind}): {runs} attacks with {model}, {price}")
    print(
        f"\nIn total {total_runs} runs, about USD {total_cost:.2f}. Tools are simulated, so nothing real runs, but "
        "each agent's instructions go to the API. Run again with --yes to start.",
    )


def _scan_target(target: Target, args: argparse.Namespace, stamp: str) -> tuple[bool, bool]:
    """Scan one target and write its report. Returns whether any attack got through, and whether the API stopped it."""
    attacks = load_attacks()
    name = model_for(target, args.model, model_from_env())
    task = args.task or default_task(target)
    folder = SCAN_RESULTS_DIR / stamp
    safe_name = "".join(character if character.isalnum() or character in "-_" else "-" for character in target.name)
    results: list[AttackResult] = []

    def on_result(result: AttackResult) -> None:
        results.append(result)
        folder.mkdir(parents=True, exist_ok=True)
        with (folder / f"{safe_name}.jsonl").open("a", encoding="utf-8") as file:
            file.write(result.transcript.model_dump_json() + "\n")
        print(f"{target.name:<24} {result.attack.id:<34} {result.outcome}  ${result.transcript.cost_usd:.4f}")

    emulator = ToolEmulator(_emulator_model(), target, task)
    stopped = False
    try:
        scan(_scan_model(name), target, attacks, task, on_result, emulator.output_for)
    except (anthropic.APIStatusError, anthropic.APIConnectionError) as error:
        stopped = True
        print(f"\nStopped {target.name} after {len(results)} runs: {error}", file=sys.stderr)
    # Runs finish in any order. The report follows the order of the attack file.
    order = [attack.id for attack in attacks]
    results.sort(key=lambda result: order.index(result.attack.id))
    findings = [*findings_from(results), *audit(target)]
    report = scan_report(target, findings, results, name, task, emulator.cost_usd)
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / f"{safe_name}.md"
    path.write_text(report, encoding="utf-8", newline="\n")
    print(f"\n{report}\nReport in {path}")
    return any(result.outcome is Outcome.GOT_THROUGH for result in results), stopped


def cmd_scan(args: argparse.Namespace) -> int:
    """Run planted attacks on each skill or agent with simulated tools. Without --yes, only print the plan."""
    targets = _targets_at(args.path)
    if not targets:
        print(f"No skill or agent files found at {args.path}.", file=sys.stderr)
        return 1
    if not args.yes:
        _print_scan_plan(targets, args)
        return 0
    stamp = datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
    try:
        outcomes = [_scan_target(target, args, stamp) for target in targets]
    except TypeError as error:
        # How the SDK reports that it found no credentials, before anything is sent.
        if "authentication method" not in str(error):
            raise
        print(_NO_API_KEY, file=sys.stderr)
        return 1
    return 1 if any(through or stopped for through, stopped in outcomes) else 0
