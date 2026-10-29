"""Detection compilers: one behavior definition -> SIEM-native rules."""

from __future__ import annotations

from collections.abc import Callable

from abm.compilers import kql, sigma, spl
from abm.models import Behavior

# target -> (compile function, file extension)
TARGETS: dict[str, tuple[Callable[[Behavior], str], str]] = {
    "kql": (kql.compile_behavior, ".kql"),
    "sigma": (sigma.compile_behavior, ".yml"),
    "spl": (spl.compile_behavior, ".spl"),
}
