"""The worst case: with a fully hijacked model, which guarantees do the guards keep?"""

from __future__ import annotations

from injectiontests.cases import Cases
from injectiontests.evaluate import summarize, worst_case, worst_case_problems
from injectiontests.models import Goal


def test_worst_case_guarantees_hold(cases: Cases) -> None:
    assert worst_case_problems(cases, worst_case(cases)) == []


def test_prompt_defenses_cannot_stop_a_hijacked_model(cases: Cases) -> None:
    rows = {row.defense.name: row for row in summarize([verdict for _, verdict in worst_case(cases)])}
    for name in ["none", "prompt", "spotlight"]:
        assert rows[name].succeeded == rows[name].attack_runs


def test_with_every_guard_only_hijacked_answers_get_through(cases: Cases) -> None:
    goals = {attack.id: attack.goal for attack in cases.attacks}
    through = [v for _, v in worst_case(cases) if v.defense == "all" and v.succeeded]
    assert through
    assert all(goals[verdict.attack or ""] is Goal.HIJACK_ANSWER for verdict in through)
