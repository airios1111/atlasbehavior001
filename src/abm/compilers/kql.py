"""Compile behaviors to KQL for Microsoft Sentinel / Defender XDR."""

from __future__ import annotations

import json
from typing import Any

from abm.compilers.common import header, kql_table, pascal, sentinel_period
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


def _conds(spec: dict[str, Any], indent: str = "    ") -> list[str]:
    return [f"{indent}| where {w}" for f, cond in spec.items() for w in _where(f, cond)]


def _provenance(b: Behavior, profile: str = "default") -> str:
    """Taint along the span graph as self-joins on an edge table, unrolled to max_hops.

    Matches the reference engine for paths up to max_hops whose spans all fall inside the rule's
    query period; the header says so in the generated rule."""
    d = b.detection
    p = d.provenance
    if p is None:  # unreachable for validated behaviors (Detection._shape)
        raise ValueError(f"{b.id}: provenance logic without a provenance block")
    tables = list(dict.fromkeys(kql_table(s.source, profile) for s in b.telemetry.required))
    n = p.max_hops
    lines = [
        header(b),
        f"// Provenance: taint from source spans along ParentSpanId and InputSpanIds edges, up to {n} hop(s),",
        "// as unrolled self-joins. Only spans inside the rule's query period are joined: set the lookback",
        "// to cover a whole agent run, or a trace that straddles the boundary is missed.",
        "// Spans ingested straight from OpenTelemetry have no InputSpanIds unless ingestion adds them; the",
        "// rule then follows parent chains only (see docs/agent-telemetry.md, Limits).",
        f"let Spans = materialize(union isfuzzy=true {', '.join(tables)}",
        "    | where isnotempty(TraceId) and isnotempty(SpanId)",
        *_conds(d.filters),
        '    | extend InputSpanIds = todynamic(column_ifexists("InputSpanIds", "")));',
        "let Edges = union",
        '    (Spans | where isnotempty(ParentSpanId)',
        '        | project TraceId, FromSpanId = ParentSpanId, ToSpanId = SpanId, Edge = "parent"),',
        "    (Spans | mv-expand FromSpanId = InputSpanIds to typeof(string) | where isnotempty(FromSpanId)",
        '        | project TraceId, FromSpanId, ToSpanId = SpanId, Edge = "input")',
        "    | where FromSpanId != ToSpanId  // self-references are malformed; the engine ignores them",
        "    | summarize Edge = take_any(Edge) by TraceId, FromSpanId, ToSpanId;",
        "let Sources = Spans",
        *_conds(p.source),
        "    | project TraceId, SourceSpanId = SpanId",
        "    | distinct TraceId, SourceSpanId;",
    ]
    prev, reached = "Sources", "SourceSpanId"
    for hop in range(1, n + 1):
        path = 'SourceSpanId' if hop == 1 else 'Path'
        lines += [
            f"let Hop{hop} = {prev}",
            f"    | join kind=inner Edges on $left.TraceId == $right.TraceId, $left.{reached} == $right.FromSpanId",
            f'    | project TraceId, SourceSpanId, ReachedSpanId = ToSpanId, Hops = {hop},',
            f'              Path = strcat({path}, " -", Edge, "-> ", ToSpanId)',
            "    | summarize Path = take_any(Path) by TraceId, SourceSpanId, ReachedSpanId, Hops;",
        ]
        prev, reached = f"Hop{hop}", "ReachedSpanId"
    lines += [
        f"union {', '.join(f'Hop{i}' for i in range(1, n + 1))}",
        "| summarize arg_min(Hops, SourceSpanId, Path) by TraceId, ReachedSpanId",
        "| join kind=inner (Spans",
        *_conds(p.sink, "        "),
        "    ) on $left.TraceId == $right.TraceId, $left.ReachedSpanId == $right.SpanId",
        "| project-away TraceId1, ReachedSpanId",
        f'| extend BehaviorId = "{b.id}", AtlasTechnique = "{b.primary_technique}",\n'
        f'         AtlasTactics = dynamic({json.dumps(b.atlas.tactics)}), Severity = "{b.severity.value}"',
    ]
    return "\n".join(lines) + "\n"


def compile_behavior(b: Behavior, profile: str = "default") -> str:
    """profile="sentinel" emits _CL custom tables and never looks back less than Sentinel's 5-minute
    minimum schedule, so a 1m window run every 5m still sees every bin."""
    d = b.detection
    if d.logic == "provenance":
        return _provenance(b, profile)
    table = kql_table(b.log_source, profile)
    lines = [header(b), table]
    if d.window:
        lookback = sentinel_period(d.window_seconds) if profile == "sentinel" else d.window
        lines.append(f"| where TimeGenerated > ago({lookback})")
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
