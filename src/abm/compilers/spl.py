"""Compile behaviors to Splunk SPL."""

from __future__ import annotations

import json
from typing import Any

from abm.compilers.common import SPL_SOURCES, header
from abm.models import Behavior

_AGG = {"count": "count", "dcount": "dc({f})", "sum": "sum({f})", "avg": "avg({f})",
        "variance": "varp({f})", "max": "max({f})", "min": "min({f})"}
_CMP = {"gt": ">", "gte": ">=", "lt": "<", "lte": "<="}


def _lit(v: Any) -> str:
    return repr(v) if isinstance(v, (int, float)) and not isinstance(v, bool) else json.dumps(str(v))


def _where(field: str, spec: Any) -> list[str]:
    if not isinstance(spec, dict):
        return [f"{field}={_lit(spec)}"]
    out = []
    for op, arg in spec.items():
        if op == "in":
            out.append(f"in({field}, {', '.join(_lit(a) for a in arg)})")
        elif op == "not_in":
            out.append(f"NOT in({field}, {', '.join(_lit(a) for a in arg)})")
        elif op == "ne":
            out.append(f"{field}!={_lit(arg)}")
        elif op == "exists":
            out.append(f"isnotnull({field})" if arg else f"isnull({field})")
        elif op == "regex":
            out.append(f"match({field}, {_lit(arg)})")
        elif op in _CMP:
            out.append(f"{field}{_CMP[op]}{_lit(arg)}")
    return out


def compile_behavior(b: Behavior) -> str:
    d = b.detection
    base = SPL_SOURCES.get(b.log_source, f'index=ai sourcetype="{b.log_source}"')
    lines = [header(b, "```"), base + (f" earliest=-{d.window}" if d.window else "")]
    for f, spec in d.filters.items():
        lines += [f"| where {w}" for w in _where(f, spec)]

    if d.logic == "signature":
        ors = [f"match({s.field}, {_lit(p)})" for s in d.signatures for p in s.patterns]
        lines.append("| where " + " OR ".join(ors))
    elif d.logic == "field_match":
        for f, spec in d.match.items():
            lines += [f"| where {w}" for w in _where(f, spec)]
    else:
        lines.append(f"| bin _time span={d.window}")
        aggs = " ".join(
            f"{_AGG[m.agg].format(f=m.field or '')} as {name}" for name, m in d.parsed_metrics.items()
        )
        lines.append(f"| stats {aggs} by {' '.join(d.group_by + ['_time'])}")
        lines.append("| where " + " AND ".join(
            f"{c.metric}{c.op}{c.value:g}" for c in d.parsed_conditions
        ))
    lines.append(
        f'| eval behavior_id="{b.id}", atlas_technique="{b.primary_technique}", '
        f'atlas_tactics="{",".join(b.atlas.tactics)}", severity="{b.severity.value}"'
    )
    return "\n".join(lines) + "\n"
