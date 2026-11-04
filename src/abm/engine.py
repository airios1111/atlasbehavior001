"""Reference detection engine: evaluates behaviors against normalized JSONL telemetry.

Used for adversarial replay, fixture tests and local triage. Production detection runs as
compiled KQL/SPL/Sigma in the SIEM; this engine is the semantic reference those must match.
"""

from __future__ import annotations

import json
import math
import operator
import re
import statistics
from collections import defaultdict
from collections.abc import Iterable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from abm import otel, provenance
from abm.catalog import AtlasCatalog
from abm.models import Behavior, Metric
from abm.response import Alert

Event = dict[str, Any]

OPS = {
    ">": operator.gt, ">=": operator.ge, "<": operator.lt,
    "<=": operator.le, "==": operator.eq, "!=": operator.ne,
}


def load_events(path: Path) -> list[Event]:
    """Normalized JSONL, one event per line. OTLP/JSON trace exports (one document per file, or one
    per line as written by the OpenTelemetry Collector file exporter) are converted to normalized
    span events; both kinds may be mixed in one file."""
    text = path.read_text(encoding="utf-8")
    objs: list[Any] = []
    if text.lstrip().startswith("{"):
        try:
            objs = [json.loads(text)]  # a single (possibly pretty-printed) JSON document
        except json.JSONDecodeError:
            objs = []
    if not objs:
        for n, line in enumerate(text.splitlines(), 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                objs.append(json.loads(line))
            except json.JSONDecodeError as e:
                raise ValueError(f"{path}:{n}: invalid JSON: {e}") from e
    events = [o for o in objs if not otel.is_otlp(o)]
    traces = [o for o in objs if otel.is_otlp(o)]
    return events + otel.from_otlp(traces) if traces else events


def _ts(ev: Event) -> float:
    v = ev.get("timestamp")
    if isinstance(v, (int, float)):
        return float(v)
    if isinstance(v, str):
        dt = datetime.fromisoformat(v.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=UTC)
        return dt.timestamp()
    raise ValueError(f"event missing/invalid timestamp: {ev!r}")


def match_value(actual: Any, spec: Any) -> bool:
    """Spec forms: scalar (equality) | {in|not_in|ne|regex|exists|gt|gte|lt|lte: ...} (AND)."""
    if isinstance(spec, dict):
        for op, arg in spec.items():
            if op == "in" and actual not in arg:
                return False
            if op == "not_in" and actual in arg:
                return False
            if op == "ne" and actual == arg:
                return False
            if op == "exists" and (actual is not None) != bool(arg):
                return False
            if op == "regex" and not (isinstance(actual, str) and re.search(arg, actual)):
                return False
            if op in ("gt", "gte", "lt", "lte"):
                if not isinstance(actual, (int, float)):
                    return False
                fn = {"gt": operator.gt, "gte": operator.ge, "lt": operator.lt, "lte": operator.le}[op]
                if not fn(actual, arg):
                    return False
        return True
    return actual == spec


def _passes(ev: Event, conds: dict[str, Any]) -> bool:
    return all(match_value(ev.get(k), v) for k, v in conds.items())


def _aggregate(m: Metric, rows: list[Event]) -> float:
    if m.agg == "count":
        return float(len(rows))
    vals = [r.get(m.field) for r in rows if r.get(m.field) is not None]  # type: ignore[arg-type]
    if m.agg == "dcount":
        return float(len({json.dumps(v, sort_keys=True) for v in vals}))
    nums = [float(v) for v in vals if isinstance(v, (int, float))]
    if not nums:
        return math.nan
    if m.agg == "sum":
        return sum(nums)
    if m.agg == "avg":
        return statistics.fmean(nums)
    if m.agg == "max":
        return max(nums)
    if m.agg == "min":
        return min(nums)
    if m.agg == "variance":
        return statistics.pvariance(nums) if len(nums) > 1 else 0.0
    raise ValueError(m.agg)


class Engine:
    def __init__(self, behaviors: Iterable[Behavior], catalog: AtlasCatalog | None = None):
        self.behaviors = list(behaviors)
        self.catalog = catalog

    def _alert(self, b: Behavior, **kw: Any) -> Alert:
        return Alert(
            behavior_id=b.id, name=b.name, severity=b.severity.value,
            technique=b.primary_technique, tactics=list(b.atlas.tactics), **kw,
        )

    def evaluate(self, b: Behavior, events: list[Event]) -> list[Alert]:
        d = b.detection
        evs = [e for e in events if _passes(e, d.filters)] if d.filters else events

        if d.logic == "signature":
            compiled = [(s.field, [re.compile(p) for p in s.patterns]) for s in d.signatures]
            alerts = []
            for e in evs:
                for fld, pats in compiled:
                    val = e.get(fld)
                    if isinstance(val, str):
                        hit = next((p.pattern for p in pats if p.search(val)), None)
                        if hit:
                            alerts.append(self._alert(
                                b, context=_ctx(e, b), evidence=[f"{fld} =~ {hit}"],
                                window_start=e.get("timestamp"),
                            ))
                            break
            return alerts

        if d.logic == "provenance":
            return self._provenance(b, evs)

        if d.logic == "field_match":
            return [
                self._alert(b, context=_ctx(e, b), evidence=[f"field_match {d.match}"],
                            window_start=e.get("timestamp"))
                for e in evs if _passes(e, d.match)
            ]

        # windowed_threshold: tumbling windows per group
        win = d.window_seconds
        buckets: dict[tuple[Any, ...], list[Event]] = defaultdict(list)
        for e in evs:
            key = tuple(e.get(g) for g in d.group_by) + (int(_ts(e) // win),)
            buckets[key].append(e)

        metrics_def = d.parsed_metrics
        conds = d.parsed_conditions
        alerts = []
        for key, rows in sorted(buckets.items(), key=lambda kv: str(kv[0])):
            values = {name: _aggregate(m, rows) for name, m in metrics_def.items()}
            if all(not math.isnan(values[c.metric]) and OPS[c.op](values[c.metric], c.value)
                   for c in conds):
                start = datetime.fromtimestamp(key[-1] * win, tz=UTC)
                alerts.append(self._alert(
                    b,
                    context=dict(zip(d.group_by, key[:-1], strict=True)),
                    metrics={k: round(v, 6) for k, v in values.items()},
                    evidence=[f"{c.metric}={values[c.metric]:.4g} {c.op} {c.value:g}" for c in conds],
                    window_start=start.isoformat(),
                ))
        return alerts

    def _provenance(self, b: Behavior, evs: list[Event]) -> list[Alert]:
        spec = b.detection.provenance
        if spec is None:  # unreachable for validated behaviors (Detection._shape)
            raise ValueError(f"{b.id}: provenance logic without a provenance block")
        findings = provenance.find(
            evs,
            is_source=lambda e: _passes(e, spec.source),
            is_sink=lambda e: _passes(e, spec.sink),
            max_hops=spec.max_hops,
        )
        alerts = []
        for f in findings:
            ctx = _ctx(f.sink, b)
            ctx.update(trace_id=f.graph.trace_id, span_id=f.sink_id, source_span_id=f.reach.source,
                       hops=f.reach.hops)
            alerts.append(self._alert(
                b, context=ctx, metrics={"hops": f.reach.hops},
                evidence=[f"path {f.describe()}", *[f"graph: {i}" for i in f.graph.issues[:3]]],
                window_start=f.sink.get("timestamp"),
            ))
        return alerts

    def run(self, events: list[Event]) -> list[Alert]:
        out: list[Alert] = []
        for b in self.behaviors:
            out.extend(self.evaluate(b, events))
        return out


def _ctx(e: Event, b: Behavior) -> dict[str, Any]:
    keep = {f for src in b.telemetry.required for f in src.fields}
    keep |= {"principal_id", "session_id", "model_id", "source_uri", "tool_name", "artifact_id",
             "trace_id", "span_id"}
    return {k: e[k] for k in keep if k in e and not isinstance(e[k], (list, dict))}


def run_tests(b: Behavior, root: Path) -> list[tuple[str, str, bool, int]]:
    """Returns (fixture, expect, passed, alert_count) per declared test."""
    eng = Engine([b])
    results = []
    for tc in b.tests:
        alerts = eng.evaluate(b, load_events(root / tc.fixture))
        passed = (len(alerts) > 0) == (tc.expect == "alert")
        results.append((tc.fixture, tc.expect, passed, len(alerts)))
    return results
