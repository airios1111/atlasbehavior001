"""Load behavior YAML files and resolve project paths."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml
from pydantic import ValidationError

from abm.models import Behavior


@dataclass
class LoadError:
    path: Path
    message: str


@dataclass
class LoadResult:
    behaviors: list[Behavior] = field(default_factory=list)
    errors: list[LoadError] = field(default_factory=list)

    def by_id(self) -> dict[str, Behavior]:
        return {b.id: b for b in self.behaviors}


def find_root(start: Path | None = None) -> Path:
    """Walk up from start until a directory containing pyproject.toml or behaviors/ is found."""
    p = (start or Path.cwd()).resolve()
    for cand in (p, *p.parents):
        if (cand / "behaviors").is_dir() or (cand / "pyproject.toml").is_file():
            return cand
    return p


def load_behaviors(path: Path) -> LoadResult:
    result = LoadResult()
    files = [path] if path.is_file() else sorted(
        [*path.rglob("*.yaml"), *path.rglob("*.yml")]
    )
    seen: dict[str, Path] = {}
    for f in files:
        try:
            raw = yaml.safe_load(f.read_text(encoding="utf-8"))
            if not isinstance(raw, dict):
                raise ValueError("top-level YAML must be a mapping")
            b = Behavior.model_validate(raw)
            b.source_path = f
        except (ValidationError, ValueError, yaml.YAMLError) as e:
            result.errors.append(LoadError(f, _fmt(e)))
            continue
        if b.id in seen:
            result.errors.append(LoadError(f, f"duplicate behavior id {b.id} (also in {seen[b.id]})"))
            continue
        seen[b.id] = f
        result.behaviors.append(b)
    return result


def _fmt(e: Exception) -> str:
    if isinstance(e, ValidationError):
        return "; ".join(
            f"{'.'.join(str(x) for x in err['loc']) or '<root>'}: {err['msg']}" for err in e.errors()
        )
    return str(e)
