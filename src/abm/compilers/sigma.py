"""Compile behaviors to Sigma (base rules + Sigma correlation rules for windowed thresholds)."""

from __future__ import annotations

import uuid
from typing import Any

import yaml

from abm.compilers.common import header
from abm.models import Behavior

_NS = uuid.UUID("8a3c0e1e-6c1f-4b7a-9d42-41b8a7d0a7f1")  # stable namespace for rule ids
_LEVEL = {"low": "low", "medium": "medium", "high": "high", "critical": "critical"}
_STATUS = {"experimental": "experimental", "test": "test", "stable": "stable",
           "deprecated": "deprecated"}
_CMP = {"gt": "gt", "gte": "gte", "lt": "lt", "lte": "lte"}
_SIGMA_COND = {">": "gt", ">=": "gte", "<": "lt", "<=": "lte", "==": "eq"}


def rule_id(behavior_id: str, suffix: str = "") -> str:
    return str(uuid.uuid5(_NS, behavior_id + suffix))


def _tags(b: Behavior) -> list[str]:
    tags = [f"atlas.{t.lower()}" for t in b.atlas.tactics]
    tags += [f"atlas.{t.id.lower()}" for t in b.atlas.techniques]
    tags += [f"attack.{t.lower()}" for t in b.attack_bridge]
    return tags


def _selection(match: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    """Split a match/filter spec into a positive selection and a negated filter block."""
    sel: dict[str, Any] = {}
    neg: dict[str, Any] = {}
    for f, spec in match.items():
        if not isinstance(spec, dict):
            sel[f] = spec
            continue
        for op, arg in spec.items():
            if op == "in":
                sel[f] = list(arg)
            elif op == "not_in":
                neg[f] = list(arg)
            elif op == "ne":
                neg[f] = arg
            elif op == "exists":
                (sel if arg else neg)[f"{f}|exists"] = True
            elif op == "regex":
                sel[f"{f}|re"] = arg
            elif op in _CMP:
                sel[f"{f}|{_CMP[op]}"] = arg
    return sel, neg


def compile_behavior(b: Behavior) -> str:
    d = b.detection
    detection: dict[str, Any] = {}
    cond_parts: list[str] = []

    if d.logic == "signature":
        for i, s in enumerate(d.signatures):
            detection[f"selection_{i}"] = {f"{s.field}|re": list(s.patterns)}
        cond_parts.append("1 of selection_*")
    else:
        sel, _neg = _selection(d.match if d.logic == "field_match" else {})
        if sel:
            detection["selection"] = sel
            cond_parts.append("selection")
    fsel, fneg = _selection(d.filters)
    if fsel:
        detection["scope"] = fsel
        cond_parts.append("scope")
    neg_all = {**fneg, **(_selection(d.match)[1] if d.logic == "field_match" else {})}
    if neg_all:
        detection["filter_exclude"] = neg_all
        cond_parts.append("not filter_exclude")
    if not any(not p.startswith("not ") for p in cond_parts):
        # no positive selection (threshold or exclusion-only): anchor on a required field
        detection["selection"] = {f"{b.telemetry.required[0].fields[0]}|exists": True}
        cond_parts.insert(0, "selection")
    detection["condition"] = " and ".join(cond_parts)

    base = {
        "title": b.name,
        "id": rule_id(b.id),
        "name": b.id.lower().replace("-", "_"),
        "status": _STATUS[b.status.value],
        "description": " ".join(b.description.split()),
        "references": b.references or None,
        "author": "atlas-behavior-map",
        "tags": _tags(b),
        "logsource": {"product": "ai", "service": b.log_source},
        "detection": detection,
        "falsepositives": d.false_positives or ["Unknown"],
        "level": _LEVEL[b.severity.value],
    }
    base = {k: v for k, v in base.items() if v is not None}
    docs = [base]

    if d.logic == "windowed_threshold":
        corr = _correlation(b)
        if corr:
            base["generate"] = True
            docs.append(corr)

    body = yaml.safe_dump_all(docs, sort_keys=False, width=120, allow_unicode=True)
    return header(b, "#") + "\n" + body


def _correlation(b: Behavior) -> dict[str, Any] | None:
    """Sigma correlation supports one event_count/value_count condition. Pick the first expressible
    one; remaining conditions are documented and must be enforced by the backend query."""
    d = b.detection
    metrics = d.parsed_metrics
    for c in d.parsed_conditions:
        m = metrics[c.metric]
        if m.agg in ("count", "dcount") and c.op in _SIGMA_COND:
            others = [x for x in d.conditions if not x.startswith(c.metric)]
            corr: dict[str, Any] = {
                "type": "event_count" if m.agg == "count" else "value_count",
                "rules": [b.id.lower().replace("-", "_")],
                "group-by": d.group_by,
                "timespan": d.window,
                "condition": {_SIGMA_COND[c.op]: int(c.value)},
            }
            if m.agg == "dcount":
                corr["condition"]["field"] = m.field
            return {
                "title": f"{b.name} (correlation)",
                "id": rule_id(b.id, ":correlation"),
                "status": _STATUS[b.status.value],
                "description": (
                    "Windowed threshold. Not expressible in Sigma correlation, enforce in backend: "
                    + "; ".join(others) if others else "Windowed threshold."
                ),
                "tags": _tags(b),
                "correlation": corr,
                "level": _LEVEL[b.severity.value],
            }
    return None
