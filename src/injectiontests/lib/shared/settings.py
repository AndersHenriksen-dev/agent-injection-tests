"""Reading config files, and the settings the whole package shares.

Each config file belongs to one Python file and mirrors its path: `lib/existing_agents/audit.py` reads
`config/existing_agents/audit.yaml`, so what a file can be set to is easy to find. Pydantic checks every file as it is
read, so a typo fails loudly when the package loads.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Literal

import yaml
from pydantic import TypeAdapter

from injectiontests.lib.shared.models import Strict

CONFIG_DIR = Path(__file__).resolve().parents[2] / "config"
_LIB_PREFIX = "injectiontests.lib."

Effort = Literal["low", "medium", "high", "xhigh", "max"]

_EFFORTS: dict[str, Effort] = {"low": "low", "medium": "medium", "high": "high", "xhigh": "xhigh", "max": "max"}


def config_path(module: str) -> Path:
    """Where a module's config file is: `injectiontests.lib.shared.claims` reads `config/shared/claims.yaml`."""
    return CONFIG_DIR.joinpath(*module.removeprefix(_LIB_PREFIX).split(".")).with_suffix(".yaml")


def read_config[T](path: Path, shape: type[T]) -> T:
    """Read one YAML file and check it against a shape, so the rest of the code works with typed objects."""
    with path.open(encoding="utf-8") as file:
        return TypeAdapter(shape).validate_python(yaml.safe_load(file))


def config_for[T](module: str, shape: type[T]) -> T:
    """Read a module's own config file. Pass `__name__`, which keeps the two paths matched."""
    return read_config(config_path(module), shape)


class Price(Strict):
    """USD per million tokens."""

    input: float
    output: float
    cache_read: float


class Settings(Strict):
    """The models, limits, prices and folders the whole package shares."""

    default_model: str
    default_effort: Effort
    max_tokens: int
    max_turns: int
    prices: dict[str, Price]
    cache_write_multiplier: float
    results_dir: Path
    scan_results_dir: Path
    evals_dir: Path


SETTINGS = config_for(__name__, Settings)


def model_from_env() -> str:
    """The model under test: INJECTIONTESTS_MODEL, or the default."""
    return os.environ.get("INJECTIONTESTS_MODEL", SETTINGS.default_model)


def effort_from_env() -> Effort:
    """The effort level: INJECTIONTESTS_EFFORT, or the default."""
    value = os.environ.get("INJECTIONTESTS_EFFORT", SETTINGS.default_effort)
    if value not in _EFFORTS:
        raise ValueError(f"INJECTIONTESTS_EFFORT must be one of {', '.join(_EFFORTS)}, not {value!r}")
    return _EFFORTS[value]
