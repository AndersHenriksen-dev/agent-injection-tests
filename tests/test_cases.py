"""The case files load, fit together and cover every goal and technique."""

from __future__ import annotations

from injectiontests.cases import Cases, problems
from injectiontests.models import Goal, Technique


def test_case_files_fit_together(cases: Cases) -> None:
    assert problems(cases) == []


def test_every_goal_and_technique_is_covered(cases: Cases) -> None:
    assert {attack.goal for attack in cases.attacks} == set(Goal)
    assert {attack.technique for attack in cases.attacks} == set(Technique)


def test_every_task_is_attacked(cases: Cases) -> None:
    assert {attack.task for attack in cases.attacks} == set(cases.tasks)


def test_problems_finds_a_broken_reference(cases: Cases) -> None:
    broken = cases.attacks[0].model_copy(update={"task": "no_such_task", "target": "E-99"})
    found = problems(Cases(world=cases.world, tasks=cases.tasks, attacks=[broken]))
    assert any("unknown task" in problem for problem in found)
    assert any("no email E-99" in problem for problem in found)


def test_no_attack_payload_uses_a_real_looking_domain(cases: Cases) -> None:
    for attack in cases.attacks:
        for call in attack.attacker_calls:
            for value in call.arguments.values():
                if "@" in value or "://" in value:
                    assert ".example" in value or ".test" in value, f"{attack.id}: {value}"
