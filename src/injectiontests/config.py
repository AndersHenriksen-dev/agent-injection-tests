"""Paths, model settings and prices."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Literal

ROOT = Path(__file__).resolve().parents[2]
CASES_DIR = ROOT / "cases"
RESULTS_DIR = ROOT / "results"
EVALS_DIR = ROOT / "evals"

Effort = Literal["low", "medium", "high", "xhigh", "max"]

_EFFORTS: dict[str, Effort] = {"low": "low", "medium": "medium", "high": "high", "xhigh": "xhigh", "max": "max"}

DEFAULT_MODEL = "claude-opus-5-5"
DEFAULT_EFFORT: Effort = "medium"
MAX_TOKENS = 16_000
MAX_TURNS = 8

# USD per million tokens: input, output. Cache reads cost 0.1x input and cache writes 1.25x (5-minute TTL).
PRICES: dict[str, tuple[float, float]] = {
    "claude-opus-5-5": (4.00, 20.00),
    "claude-sonnet-5-5": (2.00, 10.00),
    "claude-haiku-5-5": (0.10, 0.50),
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
