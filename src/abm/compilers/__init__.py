"""Detection compilers: one behavior definition -> SIEM-native rules."""

from __future__ import annotations

from collections.abc import Callable

from abm.compilers import kql, sentinel, sigma, spl
from abm.models import Behavior

# target -> (compile function, file extension)
TARGETS: dict[str, tuple[Callable[[Behavior], str], str]] = {
    "kql": (kql.compile_behavior, ".kql"),
    "sigma": (sigma.compile_behavior, ".yml"),
    "spl": (spl.compile_behavior, ".spl"),
    "sentinel": (sentinel.compile_behavior, ".yaml"),
}

# Targets whose table names follow --profile (the sentinel target always uses the sentinel profile).
PROFILED = {"kql"}


def render(target: str, b: Behavior, profile: str = "default") -> str:
    fn, _ = TARGETS[target]
    return kql.compile_behavior(b, profile=profile) if target in PROFILED else fn(b)
