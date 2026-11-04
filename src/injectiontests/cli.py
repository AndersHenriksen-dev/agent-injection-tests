"""The entry point: every command starts here.

Testing a skill or agent you own is `audit` and `scan` (`lib/existing_agents/commands.py`). The study on this repo's own
agent is `list`, `worst-case`, `run`, `eval` and `rescore` (`lib/fund_agent/commands.py`). This file only reads the
command line and hands over. `run`, `eval` and `scan` call the paid API, so `eval` and `scan` only print their plan
unless given `--yes`.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Callable
from pathlib import Path

from injectiontests.lib.existing_agents.commands import cmd_audit, cmd_scan
from injectiontests.lib.fund_agent.cases import Cases, load
from injectiontests.lib.fund_agent.commands import cmd_eval, cmd_list, cmd_rescore, cmd_run, cmd_worst_case
from injectiontests.lib.fund_agent.defenses import DEFENSES


def _with_cases(command: Callable[[Cases, argparse.Namespace], int]) -> Callable[[argparse.Namespace], int]:
    """A fund agent command, with its case files loaded when it runs."""
    return lambda args: command(load(), args)


def main() -> None:
    """Parse the command line and run a command."""
    parser = argparse.ArgumentParser(prog="injectiontests", description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)

    check = commands.add_parser("audit", help="list what to fix in a skill or agent you own (free)")
    check.add_argument("path", type=Path, help="a skill or agent file, or a folder to search")
    check.add_argument("--check", action="store_true", help="exit 1 if anything is high severity")
    check.set_defaults(run=cmd_audit)

    attack = commands.add_parser("scan", help="run planted attacks on a skill or agent you own (paid, tools simulated)")
    attack.add_argument("path", type=Path, help="a skill or agent file, or a folder to search")
    attack.add_argument("--task", help="a normal request for the agent, so that it reads something")
    attack.add_argument("--model", help="the model to test, instead of the one the file names")
    attack.add_argument("--yes", action="store_true", help="start the paid runs")
    attack.set_defaults(run=cmd_scan)

    listing = commands.add_parser("list", help="list the fund agent's tasks, attacks and defenses")
    listing.set_defaults(run=_with_cases(cmd_list))

    worst = commands.add_parser("worst-case", help="run the fund agent's cases with scripted models (free)")
    worst.add_argument("--check", action="store_true", help="exit 1 if a guard guarantee breaks")
    worst.add_argument("--write", action="store_true", help="write evals/WORST_CASE.md")
    worst.set_defaults(run=_with_cases(cmd_worst_case))

    one = commands.add_parser("run", help="run one fund agent task or attack against Claude (paid)")
    one.add_argument("--task", default="summarize_inbox")
    one.add_argument("--attack")
    one.add_argument("--defense", default="none", choices=list(DEFENSES))
    one.set_defaults(run=_with_cases(cmd_run))

    matrix = commands.add_parser("eval", help="run the fund agent's matrix against Claude (paid)")
    matrix.add_argument("--defense", nargs="*", choices=list(DEFENSES))
    matrix.add_argument("--attack", nargs="*")
    matrix.add_argument("--no-tasks", action="store_true", help="skip the runs without an attack")
    matrix.add_argument("--yes", action="store_true", help="start the paid runs")
    matrix.set_defaults(run=_with_cases(cmd_eval))

    again = commands.add_parser("rescore", help="score saved fund agent runs again with the current rules (free)")
    again.add_argument("path", type=Path, help="a runs.jsonl file from results/")
    again.add_argument("--write", action="store_true", help="write evals/RESULTS.md from a complete matrix")
    again.set_defaults(run=_with_cases(cmd_rescore))

    args = parser.parse_args()
    sys.exit(args.run(args))
