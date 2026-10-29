"""Semantic validation: ATLAS ID resolution, tactic consistency, response actions, fixtures."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from abm.catalog import AtlasCatalog
from abm.loader import LoadResult
from abm.models import Behavior, Status
from abm.response import ACTION_REGISTRY


@dataclass
class Finding:
    behavior_id: str
    level: str  # error | warning
    message: str

    def __str__(self) -> str:
        return f"[{self.level.upper():7}] {self.behavior_id}: {self.message}"


def validate(result: LoadResult, catalog: AtlasCatalog, root: Path) -> list[Finding]:
    findings: list[Finding] = []
    for err in result.errors:
        findings.append(Finding(str(err.path), "error", err.message))
    for b in result.behaviors:
        findings.extend(_check(b, catalog, root))
    return findings


def _check(b: Behavior, cat: AtlasCatalog, root: Path) -> list[Finding]:
    out: list[Finding] = []

    def err(msg: str) -> None:
        out.append(Finding(b.id, "error", msg))

    def warn(msg: str) -> None:
        out.append(Finding(b.id, "warning", msg))

    # ATLAS resolution (drift detection)
    for t in b.atlas.tactics:
        if t not in cat.tactics:
            err(f"tactic {t} not in ATLAS catalog ({cat.source} {cat.version})")
    for ref in b.atlas.techniques:
        if ref.id not in cat.techniques:
            err(f"technique {ref.id} not in ATLAS catalog ({cat.source} {cat.version})")
            continue
        if ref.relationship == "primary":
            mapped = set(cat.tactics_for(ref.id))
            if mapped and not mapped.intersection(b.atlas.tactics):
                warn(
                    f"primary technique {ref.id} belongs to {sorted(mapped)}, "
                    f"none listed in tactics {b.atlas.tactics}"
                )
    for m in b.countermeasures.mitigations:
        if m not in cat.mitigations:
            err(f"mitigation {m} not in ATLAS catalog")

    # Response actions
    for step in b.countermeasures.response:
        if step.action not in ACTION_REGISTRY:
            err(f"unknown response action '{step.action}' (registry: {sorted(ACTION_REGISTRY)})")

    # Fixtures
    for tc in b.tests:
        if not (root / tc.fixture).is_file():
            err(f"test fixture not found: {tc.fixture}")

    # Hygiene
    if not b.countermeasures.mitigations:
        warn("no ATLAS mitigations bound")
    if b.status in (Status.test, Status.stable) and not b.countermeasures.response:
        warn("no response actions defined")
    if b.status == Status.deprecated:
        warn("deprecated behavior still present")
    return out
