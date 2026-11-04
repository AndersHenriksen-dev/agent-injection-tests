"""Paths, model settings and prices."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Literal

# Inside the package, so an installed copy has them. Output paths follow the folder the command runs from.
CASES_DIR = Path(__file__).parent / "case_files"
RESULTS_DIR = Path("results")
SCAN_RESULTS_DIR = Path("injection-results")
EVALS_DIR = Path("evals")

Effort = Literal["low", "medium", "high", "xhigh", "max"]

_EFFORTS: dict[str, Effort] = {"low": "low", "medium": "medium", "high": "high", "xhigh": "xhigh", "max": "max"}

DEFAULT_MODEL = "claude-opus-5-5"
# Writes the simulated tool output in a scan. It only needs to be believable, so it is the cheapest model.
EMULATOR_MODEL = "claude-haiku-5-5"
DEFAULT_EFFORT: Effort = "medium"
MAX_TOKENS = 16_000
MAX_TURNS = 8
# A real agent doing its job takes longer than the short tasks above: 6 of 18 runs of the first scan hit a limit of 8.
SCAN_MAX_TURNS = 16
SCAN_PARALLEL_RUNS = 4

# USD per million tokens: input, output, cache read. Cache writes cost 1.25x input (5-minute TTL).
PRICES: dict[str, tuple[float, float, float]] = {
    "claude-fable-5-1": (10.00, 50.00, 0.25),
    "claude-opus-5-5": (4.00, 20.00, 0.20),
    "claude-sonnet-5-5": (2.00, 10.00, 0.20),
    "claude-haiku-5-5": (0.10, 0.50, 0.01),
}


def model_from_env() -> str:
    """The model under test: INJECTIONTESTS_MODEL, or Claude Opus 5.5."""
    return os.environ.get("INJECTIONTESTS_MODEL", DEFAULT_MODEL)


def effort_from_env() -> Effort:
    """The effort level: INJECTIONTESTS_EFFORT, or medium."""
    value = os.environ.get("INJECTIONTESTS_EFFORT", DEFAULT_EFFORT)
    if value not in _EFFORTS:
        raise ValueError(f"INJECTIONTESTS_EFFORT must be one of {', '.join(_EFFORTS)}, not {value!r}")
    return _EFFORTS[value]
