"""Per-trace provenance graph for traced agent telemetry, with taint propagation.

Events carrying `trace_id` and `span_id` (the contract in abm.telemetry) are grouped by trace. Each
trace becomes a directed graph over its spans with two edge kinds:

    parent   parent_span_id -> span_id     the step that caused this one
    input    input_span_ids -> span_id     a step whose output this one consumed

Taint starts at spans matching a behavior's `source` spec and spreads along edges. A span matching
`sink` that is reached within `max_hops` edges is a finding. Distance is the shortest path from any
source; a source never reaches itself at distance zero.

Malformed traces are evaluated as far as they go and described in `TraceGraph.issues`: references
to spans that are missing from the trace drop that edge, duplicate span ids are merged, cycles are
reported (propagation still terminates because each span keeps only its shortest distance).
"""

from __future__ import annotations

from collections import deque
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from typing import Any

from abm.telemetry import check_span

Event = dict[str, Any]
Predicate = Callable[[Event], bool]


@dataclass
class TraceGraph:
    trace_id: str
    spans: dict[str, Event] = field(default_factory=dict)
    edges: dict[str, list[tuple[str, str]]] = field(default_factory=dict)  # from -> [(to, kind)]
    issues: list[str] = field(default_factory=list)

    def successors(self, span_id: str) -> list[tuple[str, str]]:
        return self.edges.get(span_id, [])

    def label(self, span_id: str) -> str:
        ev = self.spans[span_id]
        what = ev.get("tool_name") or ev.get("operation") or ev.get("input_origin") or "span"
        return f"{span_id}({what})"


@dataclass
class Reach:
    """How taint reached a span: shortest distance, the source it came from, and the path."""

    hops: int
    source: str
    path: list[tuple[str, str]]  # [(span_id, kind of the edge into it)]; path[0] is the source, kind ""


@dataclass
class Finding:
    graph: TraceGraph
    sink_id: str
    reach: Reach
    nested: list[str] = field(default_factory=list)  # reached sinks below this one, folded in

    @property
    def sink(self) -> Event:
        return self.graph.spans[self.sink_id]

    def describe(self) -> str:
        parts = [self.graph.label(self.reach.path[0][0])]
        parts += [f"-{kind}-> {self.graph.label(sid)}" for sid, kind in self.reach.path[1:]]
        text = f"{' '.join(parts)} ({self.reach.hops} hop(s))"
        if self.nested:
            text += f"; nested sink span(s) {', '.join(self.graph.label(n) for n in self.nested)}"
        return text


def _ids(value: Any) -> list[str]:
    if value is None or value == "":
        return []
    if isinstance(value, (list, tuple)):
        return [str(v) for v in value if v not in (None, "")]
    return [str(value)]


def build_graphs(events: Iterable[Event]) -> dict[str, TraceGraph]:
    """Group traced events by trace_id and link their spans. Events without trace/span ids are skipped."""
    graphs: dict[str, TraceGraph] = {}
    for ev in events:
        tid, sid = ev.get("trace_id"), ev.get("span_id")
        if not tid or not sid:
            continue
        tid, sid = str(tid), str(sid)
        g = graphs.setdefault(tid, TraceGraph(tid))
        for problem in check_span(ev):
            g.issues.append(f"span {sid}: {problem}")
        if sid in g.spans:
            g.spans[sid] = _merge(g, sid, g.spans[sid], ev)
        else:
            g.spans[sid] = dict(ev)
    for g in graphs.values():
        _link(g)
    return graphs


def _merge(g: TraceGraph, sid: str, first: Event, again: Event) -> Event:
    """The same span reported twice (e.g. by the agent runtime and the MCP gateway): earlier values
    win, later reports fill gaps, input edges are unioned."""
    p1, p2 = first.get("parent_span_id"), again.get("parent_span_id")
    if p1 and p2 and p1 != p2:
        g.issues.append(f"span {sid}: conflicting parent_span_id {p1!r} vs {p2!r}; kept {p1!r}")
    else:
        g.issues.append(f"span {sid}: reported more than once; merged")
    merged = {**again, **{k: v for k, v in first.items() if v is not None}}
    inputs = _ids(first.get("input_span_ids")) + _ids(again.get("input_span_ids"))
    if inputs:
        merged["input_span_ids"] = list(dict.fromkeys(inputs))
    return merged


def _link(g: TraceGraph) -> None:
    missing: set[str] = set()
    seen: set[tuple[str, str]] = set()

    def add(src: str, dst: str, kind: str) -> None:
        if src == dst:
            g.issues.append(f"span {dst}: references itself as {kind}; ignored")
            return
        if src not in g.spans:
            missing.add(src)
            return
        if (src, dst) not in seen:
            seen.add((src, dst))
            g.edges.setdefault(src, []).append((dst, kind))

    for sid, ev in g.spans.items():
        for parent in _ids(ev.get("parent_span_id")):
            add(parent, sid, "parent")
        for src in _ids(ev.get("input_span_ids")):
            add(src, sid, "input")
    if missing:
        g.issues.append(f"{len(missing)} referenced span(s) not in trace (edges dropped): "
                        f"{', '.join(sorted(missing)[:5])}{' ...' if len(missing) > 5 else ''}")
    cyclic = _cyclic_nodes(g)
    if cyclic:
        g.issues.append(f"cycle among spans {', '.join(sorted(cyclic)[:5])}; graph is not a DAG")


def _cyclic_nodes(g: TraceGraph) -> set[str]:
    """Kahn's algorithm: whatever cannot be topologically ordered sits on or behind a cycle."""
    indeg = dict.fromkeys(g.spans, 0)
    for outs in g.edges.values():
        for dst, _ in outs:
            indeg[dst] += 1
    queue = deque(s for s, d in indeg.items() if d == 0)
    while queue:
        s = queue.popleft()
        for dst, _ in g.successors(s):
            indeg[dst] -= 1
            if indeg[dst] == 0:
                queue.append(dst)
    return {s for s, d in indeg.items() if d > 0}


def propagate(g: TraceGraph, is_source: Predicate, max_hops: int) -> dict[str, Reach]:
    """Multi-source BFS. Returns every span reached from a source within max_hops (distance >= 1)."""
    order = sorted(g.spans, key=lambda s: (str(g.spans[s].get("timestamp", "")), s))
    sources = [s for s in order if is_source(g.spans[s])]
    best: dict[str, Reach] = {}
    queue: deque[tuple[str, int, str, list[tuple[str, str]]]] = deque(
        (s, 0, s, [(s, "")]) for s in sources
    )
    while queue:
        node, dist, src, path = queue.popleft()
        if dist >= max_hops:
            continue
        for dst, kind in g.successors(node):
            d = dist + 1
            if dst in best and best[dst].hops <= d:
                continue
            reach = Reach(d, src, [*path, (dst, kind)])
            best[dst] = reach
            queue.append((dst, d, src, reach.path))
    return best


def find(events: Iterable[Event], is_source: Predicate, is_sink: Predicate,
         max_hops: int) -> list[Finding]:
    """Every sink span reached by taint within max_hops, one finding per (trace, sink).

    One action often appears as nested spans (the agent's execute_tool span and the MCP client span
    under it); a reached sink whose parent chain contains another reached sink is folded into the
    outermost one instead of producing a second finding."""
    out: list[Finding] = []
    for tid in sorted(graphs := build_graphs(events)):
        g = graphs[tid]
        hits = {sid: r for sid, r in propagate(g, is_source, max_hops).items() if is_sink(g.spans[sid])}
        outer: dict[str, Finding] = {}
        for sid in hits:
            top = _outermost(g, sid, hits)
            if top == sid:
                outer.setdefault(sid, Finding(g, sid, hits[sid]))
            else:
                outer.setdefault(top, Finding(g, top, hits[top])).nested.append(sid)
        out.extend(outer.values())
    out.sort(key=lambda f: (str(f.sink.get("timestamp", "")), f.graph.trace_id, f.sink_id))
    return out


def _outermost(g: TraceGraph, sid: str, hits: dict[str, Reach]) -> str:
    top, seen = sid, {sid}
    parent = g.spans[sid].get("parent_span_id")
    while parent and parent in g.spans and parent not in seen:
        seen.add(parent)
        if parent in hits:
            top = parent
        parent = g.spans[parent].get("parent_span_id")
    return top
