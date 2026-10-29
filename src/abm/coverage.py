"""Coverage scoring against the ATLAS matrix, gap listing, and ATLAS Navigator layer output."""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path

from abm.catalog import AtlasCatalog
from abm.engine import run_tests
from abm.models import Behavior, Status
from abm.response import ACTION_REGISTRY

SCORE_LABEL = {
    0: "none",
    1: "mitigation-only",
    2: "detection",
    3: "detection + automated response (replay passing)",
}
SCORE_COLOR = {0: "#ffffff", 1: "#fde68a", 2: "#93c5fd", 3: "#34d399"}


@dataclass
class TechniqueCoverage:
    technique: str
    name: str
    tactics: list[str]
    score: int = 0
    behaviors: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


def _behavior_score(b: Behavior, root: Path) -> tuple[int, str]:
    if b.status == Status.deprecated:
        return 0, "deprecated"
    if b.status == Status.experimental:
        return (1, "experimental detection") if b.countermeasures.mitigations else (0, "experimental, no mitigations")
    score, note = 2, f"{b.status.value} detection"
    if b.status == Status.stable:
        auto = [s for s in b.countermeasures.response
                if not (s.requires_approval if s.requires_approval is not None
                        else ACTION_REGISTRY.get(s.action, ACTION_REGISTRY["notify"]).requires_approval)]
        results = run_tests(b, root)
        if auto and results and all(r[2] for r in results):
            score, note = 3, "stable, auto-response, replay passing"
        elif not all(r[2] for r in results):
            note = "stable but replay FAILING"
    return score, note


def compute(behaviors: list[Behavior], catalog: AtlasCatalog, root: Path) -> dict[str, TechniqueCoverage]:
    cov = {
        tid: TechniqueCoverage(tid, catalog.name(tid), list(e.tactics))
        for tid, e in catalog.techniques.items()
    }
    for b in behaviors:
        s, note = _behavior_score(b, root)
        for ref in b.atlas.techniques:
            if ref.relationship == "precondition" or ref.id not in cov:
                continue
            c = cov[ref.id]
            c.behaviors.append(b.id)
            c.notes.append(f"{b.id}: {note}")
            c.score = max(c.score, s)
    return cov


def gaps(cov: dict[str, TechniqueCoverage], tactic: str | None = None, below: int = 1) -> list[TechniqueCoverage]:
    return [c for c in cov.values()
            if c.score < below and (tactic is None or tactic in c.tactics)]


def _shortname(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")


def navigator_layer(cov: dict[str, TechniqueCoverage], catalog: AtlasCatalog, name: str = "ATLAS Behavior Map coverage") -> dict:
    techniques = []
    for c in cov.values():
        if c.score == 0:
            continue
        for tac in c.tactics or [""]:
            entry = {
                "techniqueID": c.technique,
                "score": c.score,
                "color": SCORE_COLOR[c.score],
                "comment": f"{SCORE_LABEL[c.score]} | " + "; ".join(c.notes),
                "metadata": [{"name": "behaviors", "value": ", ".join(c.behaviors)}],
                "enabled": True,
            }
            if tac and tac in catalog.tactics:
                entry["tactic"] = _shortname(catalog.tactics[tac].name)
            techniques.append(entry)
    return {
        "name": name,
        "versions": {"layer": "4.5", "navigator": "4.9.1"},
        "domain": "atlas-atlas",
        "description": f"Generated from behaviors; catalog {catalog.source} {catalog.version}",
        "gradient": {"colors": [SCORE_COLOR[0], SCORE_COLOR[3]], "minValue": 0, "maxValue": 3},
        "legendItems": [{"label": f"{k}: {v}", "color": SCORE_COLOR[k]} for k, v in SCORE_LABEL.items()],
        "techniques": techniques,
    }


def markdown_report(cov: dict[str, TechniqueCoverage], catalog: AtlasCatalog) -> str:
    total = len(cov)
    covered = sum(1 for c in cov.values() if c.score >= 2)
    lines = [
        "# ATLAS Coverage Report", "",
        f"Catalog: `{catalog.source}` version `{catalog.version}`  ",
        f"Techniques with detection (score >= 2): **{covered}/{total}** "
        f"({(covered / total * 100 if total else 0):.0f}%)", "",
    ]
    for tac_id, tac in catalog.tactics.items():
        rows = [c for c in cov.values() if tac_id in c.tactics]
        if not rows:
            continue
        lines += [f"## {tac.name} ({tac_id})", "", "| Technique | Name | Score | Behaviors |", "|---|---|---|---|"]
        for c in sorted(rows, key=lambda r: r.technique):
            lines.append(f"| {c.technique} | {c.name} | {c.score} ({SCORE_LABEL[c.score]}) | "
                         f"{', '.join(c.behaviors) or '—'} |")
        lines.append("")
    return "\n".join(lines)


def write_reports(cov: dict[str, TechniqueCoverage], catalog: AtlasCatalog, out_dir: Path, layer_path: Path | None = None) -> list[Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    layer_path = layer_path or out_dir / "atlas-layer.json"
    layer_path.parent.mkdir(parents=True, exist_ok=True)
    paths = {
        out_dir / "coverage.md": markdown_report(cov, catalog),
        out_dir / "coverage.json": json.dumps([asdict(c) for c in cov.values()], indent=2),
        out_dir / "gaps.json": json.dumps([asdict(c) for c in gaps(cov)], indent=2),
        layer_path: json.dumps(navigator_layer(cov, catalog), indent=2),
    }
    for p, content in paths.items():
        p.write_text(content + "\n", encoding="utf-8")
    return list(paths)
