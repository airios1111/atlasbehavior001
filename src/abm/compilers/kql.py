"""Compile behaviors to KQL for Microsoft Sentinel / Defender XDR."""

from __future__ import annotations

import json
from typing import Any

from abm.compilers.common import KQL_TABLES, header, pascal
from abm.models import Behavior

_AGG = {"count": "count()", "dcount": "dcount({f})", "sum": "sum({f})", "avg": "avg({f})",
        "variance": "variance({f})", "max": "max({f})", "min": "min({f})"}
_CMP = {"gt": ">", "gte": ">=", "lt": "<", "lte": "<="}


def _lit(v: Any) -> str:
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (int, float)):
        return repr(v)
    return json.dumps(str(v))


def _rx(pattern: str) -> str:
    """KQL verbatim string literal: double any embedded quotes."""
    return '@"' + pattern.replace('"', '""') + '"'


def _where(field: str, spec: Any) -> list[str]:
    col = pascal(field)
    if not isinstance(spec, dict):
        return [f"{col} == {_lit(spec)}"]
    out = []
    for op, arg in spec.items():
        if op == "in":
            out.append(f"{col} in ({', '.join(_lit(a) for a in arg)})")
        elif op == "not_in":
            out.append(f"{col} !in ({', '.join(_lit(a) for a in arg)})")
        elif op == "ne":
            out.append(f"{col} != {_lit(arg)}")
        elif op == "exists":
            out.append(f"isnotempty({col})" if arg else f"isempty({col})")
        elif op == "regex":
            out.append(f"{col} matches regex {_rx(arg)}")
        elif op in _CMP:
            out.append(f"{col} {_CMP[op]} {_lit(arg)}")
    return out


def compile_behavior(b: Behavior) -> str:
    d = b.detection
    table = KQL_TABLES.get(b.log_source, pascal(b.log_source))
    lines = [header(b), table]
    if d.window:
        lines.append(f"| where TimeGenerated > ago({d.window})")
    for f, spec in d.filters.items():
        lines += [f"| where {w}" for w in _where(f, spec)]

    if d.logic == "signature":
        ors = []
        for s in d.signatures:
            col = pascal(s.field)
            ors += [f"{col} matches regex {_rx(p)}" for p in s.patterns]
        lines.append("| where " + "\n    or ".join(ors))
    elif d.logic == "field_match":
        for f, spec in d.match.items():
            lines += [f"| where {w}" for w in _where(f, spec)]
    else:
        aggs = ",\n            ".join(
            f"{pascal(name)} = {_AGG[m.agg].format(f=pascal(m.field or ''))}"
            for name, m in d.parsed_metrics.items()
        )
        by = ", ".join([pascal(g) for g in d.group_by] + [f"bin(TimeGenerated, {d.window})"])
        lines.append(f"| summarize {aggs}\n          by {by}")
        conds = " and ".join(f"{pascal(c.metric)} {c.op} {c.value:g}" for c in d.parsed_conditions)
        lines.append(f"| where {conds}")

    lines.append(
        f'| extend BehaviorId = "{b.id}", AtlasTechnique = "{b.primary_technique}",\n'
        f'         AtlasTactics = dynamic({json.dumps(b.atlas.tactics)}), Severity = "{b.severity.value}"'
    )
    return "\n".join(lines) + "\n"
