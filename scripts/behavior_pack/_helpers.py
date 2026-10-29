"""Builders for behavior-pack specs: detection shapes, response steps and fixture events."""

from __future__ import annotations

import random
from datetime import UTC, datetime, timedelta
from typing import Any

T0 = datetime(2026, 10, 1, 14, 0, 0, tzinfo=UTC)  # aligned to minute/hour buckets
RNG = random.Random(7001)

# normalized log sources (see src/abm/compilers/common.py)
LLM = "llm_gateway"
RET = "llm_retrieval"
INF = "inference_gateway"
REG = "model_registry"
AGT = "agent_runtime"
TRN = "training_pipeline"
IDN = "identity"
VEC = "vector_store"
MEM = "agent_memory"
MCP = "mcp_gateway"
WS = "ml_workspace"
AUD = "cloud_audit"


def ts(seconds: float) -> str:
    return (T0 + timedelta(seconds=seconds)).isoformat().replace("+00:00", "Z")


# ---------------------------------------------------------------- fixture events
def rows(n: int, step: float = 1.0, start: float = 0.0, **fields: Any) -> list[dict]:
    """n events, `step` seconds apart. Callable field values receive the row index."""
    return [
        {"timestamp": ts(start + i * step),
         **{k: (v(i) if callable(v) else v) for k, v in fields.items()}}
        for i in range(n)
    ]


def texts(field: str, items: list[str], step: float = 10, start: float = 0, **base: Any) -> list[dict]:
    """One event per text, all sharing `base` fields."""
    return [{"timestamp": ts(start + i * step), **base, field: t} for i, t in enumerate(items)]


def events(*items: dict, step: float = 5) -> list[dict]:
    """Explicit events, timestamps assigned in order."""
    return [{"timestamp": ts(i * step), **e} for i, e in enumerate(items)]


# ---------------------------------------------------------------- detection shapes
def sig(field: str, *patterns: str, filters: dict | None = None, fp: tuple[str, ...] = ()) -> dict:
    d: dict[str, Any] = {"logic": "signature"}
    if filters:
        d["filters"] = filters
    d["signatures"] = [{"field": field, "patterns": list(patterns)}]
    if fp:
        d["false_positives"] = list(fp)
    return d


def fm(match: dict, filters: dict | None = None, fp: tuple[str, ...] = ()) -> dict:
    d: dict[str, Any] = {"logic": "field_match"}
    if filters:
        d["filters"] = filters
    d["match"] = match
    if fp:
        d["false_positives"] = list(fp)
    return d


def thr(window: str, group_by: list[str], metrics: dict[str, str], conditions: list[str],
        filters: dict | None = None, fp: tuple[str, ...] = ()) -> dict:
    d: dict[str, Any] = {"logic": "windowed_threshold", "window": window, "group_by": group_by}
    if filters:
        d["filters"] = filters
    d["metrics"] = metrics
    d["conditions"] = conditions
    if fp:
        d["false_positives"] = list(fp)
    return d


def act(action: str, **params: Any) -> dict:
    return {"action": action, "params": params}


# ---------------------------------------------------------------- spec
def B(id: str, category: str, name: str, severity: str, confidence: str, description: str,
      primary: str, *, source: str, fields: list[str], detection: dict, mitigations: list[str],
      response: list[dict], attack: list[dict], benign: list[dict], secondary: tuple[str, ...] = (),
      pre: bool = False, tactics: list[str] | None = None, attack_bridge: tuple[str, ...] = ()) -> dict:
    """One behavior. `pre` adds AML.T0040 (inference API access) as a precondition.
    `tactics` defaults to the primary technique's tactics in the pinned ATLAS catalog."""
    techniques = [{"id": primary, "relationship": "primary"}]
    techniques += [{"id": s, "relationship": "secondary"} for s in secondary]
    if pre:
        techniques.append({"id": "AML.T0040", "relationship": "precondition"})
    return {
        "id": f"BHV-{id}", "category": category, "name": name, "severity": severity,
        "confidence": confidence, "description": description, "primary": primary,
        "techniques": techniques, "tactics": tactics, "attack_bridge": list(attack_bridge),
        "source": source, "fields": ["timestamp", *fields], "detection": detection,
        "mitigations": mitigations, "response": response, "attack": attack, "benign": benign,
    }
