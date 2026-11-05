"""Running tasks and attacks under every defense, and turning the verdicts into a results table.

Two kinds of run share this code. The worst case uses scripted models and no API: a fully hijacked model for each
attack, and a correct model for each task. The real eval uses Claude and costs money.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Iterator
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path

from injectiontests.lib.fund_agent.agent import run
from injectiontests.lib.fund_agent.cases import Cases
from injectiontests.lib.fund_agent.defenses import DEFENSES, Defense
from injectiontests.lib.fund_agent.scoring import score
from injectiontests.lib.shared.loop import Model, ScriptedModel
from injectiontests.lib.shared.models import Attack, Goal, Strict, Task, Technique, Transcript, Verdict
from injectiontests.lib.shared.settings import config_for

Result = tuple[Transcript, Verdict]


class _EvaluateConfig(Strict):
    parallel_runs: int


_CONFIG = config_for(__name__, _EvaluateConfig)


@dataclass(frozen=True)
class Row:
    """One defense's line in the results table."""

    defense: Defense
    attack_runs: int
    attempted: int
    succeeded: int
    per_pass: list[int]
    warned: int
    task_runs: int
    tasks_done: int
    attack_tasks_done: int
    refusals: int
    cost_usd: float
    seconds: float


def run_one(
    model: Model,
    cases: Cases,
    task: Task,
    attack: Attack | None,
    defense: Defense,
    pass_number: int = 1,
) -> Result:
    """Run and score one task, with or without an attack, under one defense."""
    transcript = run(model, cases.world, task, attack, defense)
    transcript.pass_number = pass_number
    return transcript, score(transcript, task, attack, cases.world)


def plan(
    cases: Cases,
    defenses: list[Defense],
    attacks: list[Attack],
    with_tasks: bool,
) -> Iterator[tuple[Task, Attack | None, Defense]]:
    """Every run in a matrix: each task without an attack, then each attack, for each defense."""
    for defense in defenses:
        if with_tasks:
            for task in cases.tasks.values():
                yield task, None, defense
        for attack in attacks:
            yield cases.tasks[attack.task], attack, defense


def run_matrix(
    model: Model,
    cases: Cases,
    defenses: list[Defense],
    attacks: list[Attack],
    with_tasks: bool,
    on_result: Callable[[Result], None],
    passes: int = 1,
    saved: frozenset[tuple[str, str | None, str, int]] = frozenset(),
) -> None:
    """Run the matrix `passes` times with one model, a few runs at a time, handing over each result when it is done.

    Runs in `saved`, as (task, attack, defense, pass), are already paid for and are skipped.
    """
    with ThreadPoolExecutor(max_workers=_CONFIG.parallel_runs) as pool:
        runs = [
            pool.submit(run_one, model, cases, task, attack, defense, pass_number)
            for pass_number in range(1, passes + 1)
            for task, attack, defense in plan(cases, defenses, attacks, with_tasks)
            if (task.id, attack.id if attack else None, defense.name, pass_number) not in saved
        ]
        try:
            for done in as_completed(runs):
                on_result(done.result())
        except BaseException:
            pool.shutdown(wait=True, cancel_futures=True)
            raise


def worst_case(cases: Cases) -> list[Result]:
    """Every attack with a fully hijacked model, and every task with a correct one, under every defense."""
    results: list[Result] = []
    for defense in DEFENSES.values():
        for task in cases.tasks.values():
            results.append(
                run_one(ScriptedModel(task.reference_calls, task.reference_answer), cases, task, None, defense),
            )
        for attack in cases.attacks:
            hijacked = ScriptedModel(attack.attacker_calls, attack.attacker_answer)
            results.append(run_one(hijacked, cases, cases.tasks[attack.task], attack, defense))
    return results


def worst_case_problems(cases: Cases, results: list[Result]) -> list[str]:
    """What the worst case must show: attacks work with no defense, guards stop all but hijacked answers, tasks work."""
    goals = {attack.id: attack.goal for attack in cases.attacks}
    found: list[str] = []
    for _, verdict in results:
        where = f"{verdict.defense}: {verdict.attack or verdict.task}"
        if verdict.attack is None and not verdict.task_done:
            found.append(f"{where}: a correct run of the task fails, so the defense blocks real work")
        if verdict.attack is not None and verdict.defense == "none" and not verdict.succeeded:
            found.append(f"{where}: the attacker's own calls do not reach the goal, so the case is broken")
        if verdict.defense == "all" and verdict.succeeded and goals.get(verdict.attack or "") is not Goal.HIJACK_ANSWER:
            found.append(f"{where}: gets through every guard")
    return found


def summarize(verdicts: list[Verdict]) -> list[Row]:
    """One row per defense, in the order the defenses are defined."""
    rows: list[Row] = []
    for defense in DEFENSES.values():
        mine = [verdict for verdict in verdicts if verdict.defense == defense.name]
        if not mine:
            continue
        attacks = [verdict for verdict in mine if verdict.attack is not None]
        tasks = [verdict for verdict in mine if verdict.attack is None]
        rows.append(
            Row(
                defense=defense,
                attack_runs=len(attacks),
                attempted=sum(verdict.attempted for verdict in attacks),
                succeeded=sum(verdict.succeeded for verdict in attacks),
                per_pass=[
                    sum(verdict.succeeded for verdict in attacks if verdict.pass_number == number)
                    for number in sorted({verdict.pass_number for verdict in attacks})
                ],
                warned=sum(verdict.warned for verdict in attacks),
                task_runs=len(tasks),
                tasks_done=sum(verdict.task_done for verdict in tasks),
                attack_tasks_done=sum(verdict.task_done for verdict in attacks),
                refusals=sum(verdict.refused for verdict in mine),
                cost_usd=sum(verdict.cost_usd for verdict in mine),
                seconds=sum(verdict.seconds for verdict in mine),
            ),
        )
    return rows


def _share(part: int, whole: int) -> str:
    return f"{part} of {whole}" if whole else "-"


def table(rows: list[Row], with_model_columns: bool) -> str:
    """The results as a Markdown table.

    Claims rejected, the task under attack, refusals, cost and time only mean something for a real model: a scripted
    hijacked model never warns anyone or does the task, and costs nothing. Claims rejected are the answers the scoring
    did not count as hijacked although they repeat the claim, so they are the ones to read when checking a run.
    """
    head = ["Defense", "Attacks that got through", "Attacks the model tried", "Tasks done"]
    repeated = with_model_columns and any(len(row.per_pass) > 1 for row in rows)
    if repeated:
        head.insert(2, "Got through in each pass")
    if with_model_columns:
        head += ["Claims quoted and rejected or doubted", "Tasks done under attack", "Refusals", "Cost per run (USD)"]
        head += ["Seconds per run"]
    lines = ["| " + " | ".join(head) + " |", "|" + "---|" * len(head)]
    for row in rows:
        runs = row.attack_runs + row.task_runs
        cells = [
            f"`{row.defense.name}`: {row.defense.description}",
            _share(row.succeeded, row.attack_runs),
            _share(row.attempted, row.attack_runs),
            _share(row.tasks_done, row.task_runs),
        ]
        if repeated:
            cells.insert(2, ", ".join(str(count) for count in row.per_pass))
        if with_model_columns:
            cells += [
                str(row.warned),
                _share(row.attack_tasks_done, row.attack_runs),
                str(row.refusals),
                f"{row.cost_usd / runs:.4f}",
                f"{row.seconds / runs:.1f}",
            ]
        lines.append("| " + " | ".join(cells) + " |")
    return "\n".join(lines)


def by_goal(cases: Cases, verdicts: list[Verdict]) -> str:
    """Attacks that got through, per defense and attacker goal, as a Markdown table."""
    goals = {attack.id: attack.goal for attack in cases.attacks}
    defenses = [d for d in DEFENSES.values() if any(v.defense == d.name for v in verdicts)]
    lines = ["| Goal | " + " | ".join(f"`{d.name}`" for d in defenses) + " |", "|" + "---|" * (len(defenses) + 1)]
    for goal in Goal:
        cells = []
        for defense in defenses:
            mine = [v for v in verdicts if v.defense == defense.name and v.attack and goals[v.attack] is goal]
            cells.append(_share(sum(v.succeeded for v in mine), len(mine)))
        lines.append(f"| {goal.value} | " + " | ".join(cells) + " |")
    return "\n".join(lines)


def by_technique(cases: Cases, verdicts: list[Verdict]) -> str:
    """Attacks that got through, per defense and technique, as a Markdown table."""
    techniques = {attack.id: attack.technique for attack in cases.attacks}
    defenses = [d for d in DEFENSES.values() if any(v.defense == d.name for v in verdicts)]
    lines = ["| Technique | " + " | ".join(f"`{d.name}`" for d in defenses) + " |", "|" + "---|" * (len(defenses) + 1)]
    for technique in Technique:
        cells = []
        for defense in defenses:
            mine = [v for v in verdicts if v.defense == defense.name and v.attack and techniques[v.attack] is technique]
            cells.append(_share(sum(v.succeeded for v in mine), len(mine)))
        lines.append(f"| {technique.value} | " + " | ".join(cells) + " |")
    return "\n".join(lines)


def append_result(result: Result, path: Path) -> None:
    """Add one transcript and verdict to a JSON Lines file, so a run is kept as soon as it is paid for."""
    transcript, verdict = result
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as file:
        file.write(json.dumps({"transcript": transcript.model_dump(), "verdict": verdict.model_dump()}) + "\n")


def read_results(path: Path, cases: Cases) -> list[Result]:
    """Read saved transcripts and score them with the current rules, so a scoring change needs no new API calls.

    The verdicts saved beside the transcripts are ignored: they show the rules at the time of the run.
    """
    attacks = {attack.id: attack for attack in cases.attacks}
    results: list[Result] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        transcript = Transcript.model_validate(json.loads(line)["transcript"])
        attack = attacks[transcript.attack] if transcript.attack else None
        results.append((transcript, score(transcript, cases.tasks[transcript.task], attack, cases.world)))
    return results
