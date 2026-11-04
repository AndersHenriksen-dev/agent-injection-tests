"""Loading the world, task and attack files, and checking that they fit together."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import yaml
from pydantic import TypeAdapter

from injectiontests.config import CASES_DIR
from injectiontests.models import Attack, Channel, Goal, Task, World
from injectiontests.world import TOOLS


@dataclass(frozen=True)
class Cases:
    """The world, the tasks by id and the attacks, as loaded from `case_files/`."""

    world: World
    tasks: dict[str, Task]
    attacks: list[Attack]


def _read(path: Path) -> object:
    """Parse a YAML file. The result is untyped until a model validates it."""
    with path.open(encoding="utf-8") as file:
        return yaml.safe_load(file)


def problems(cases: Cases) -> list[str]:
    """Everything wrong with how the files refer to each other. An empty list means they fit."""
    found: list[str] = []
    for task in cases.tasks.values():
        unknown = [tool for tool in [*task.tools, *(a.tool for a in task.allowed_actions)] if tool not in TOOLS]
        found += [f"task {task.id}: unknown tool {tool}" for tool in unknown]
        found += [
            f"task {task.id}: reference call to {c.tool} not in its tools"
            for c in task.reference_calls
            if c.tool not in task.tools
        ]
    targets: dict[Channel, set[str]] = {
        Channel.EMAIL: set(cases.world.emails),
        Channel.DOCUMENT: set(cases.world.documents),
        Channel.PAGE: set(cases.world.pages),
    }
    for attack in cases.attacks:
        if attack.task not in cases.tasks:
            found.append(f"attack {attack.id}: unknown task {attack.task}")
        if attack.target not in targets[attack.channel]:
            found.append(f"attack {attack.id}: no {attack.channel} {attack.target}")
        found += [f"attack {attack.id}: unknown tool {c.tool}" for c in attack.attacker_calls if c.tool not in TOOLS]
        if attack.goal is Goal.HIJACK_ANSWER and not attack.marker:
            found.append(f"attack {attack.id}: hijack_answer needs a marker")
        # A URL in the answer is enough for exfiltrate_url: rendering a link or image sends the request.
        leaks_in_answer = attack.goal is Goal.EXFILTRATE_URL and "http" in attack.attacker_answer
        if attack.goal is not Goal.HIJACK_ANSWER and not attack.attacker_calls and not leaks_in_answer:
            found.append(f"attack {attack.id}: needs attacker_calls")
    ids = [attack.id for attack in cases.attacks]
    found += [f"attack id {i} is used twice" for i in sorted({i for i in ids if ids.count(i) > 1})]
    return found


def load(directory: Path = CASES_DIR) -> Cases:
    """Load and check `world.yaml`, `tasks.yaml` and `attacks.yaml`.

    Raises:
        ValueError: The files do not fit together.
    """
    world = World.model_validate(_read(directory / "world.yaml"))
    tasks = TypeAdapter(list[Task]).validate_python(_read(directory / "tasks.yaml"))
    attacks = TypeAdapter(list[Attack]).validate_python(_read(directory / "attacks.yaml"))
    cases = Cases(world=world, tasks={task.id: task for task in tasks}, attacks=attacks)
    if found := problems(cases):
        raise ValueError("Case files do not fit together:\n" + "\n".join(found))
    return cases
