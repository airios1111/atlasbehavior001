"""OpenTelemetry adapter: OTLP/JSON trace exports -> normalized agent span events.

Accepts ExportTraceServiceRequest documents (`{"resourceSpans": [...]}`), either one document per
file or one per line as written by the OpenTelemetry Collector file exporter.

Attribute names follow the OpenTelemetry GenAI and MCP semantic conventions. Checked against
opentelemetry-semantic-conventions 0.66b1 (schema 1.44.0), where the gen_ai.* and mcp.* attributes
are marked "moved to open-telemetry/semantic-conventions-genai" with unchanged names; definitions
were read from 0.64b0 (schema 1.41.1), the last release that ships them in full. The conventions are
in Development status and may still change.

The conventions have no notion of trust or tool impact. Deployments add those as `abm.*` span
attributes (for example with a Collector transform processor fed by the tool registry); any
`abm.<field>` attribute is copied to `<field>` and takes precedence over inferred values.
"""

from __future__ import annotations

import base64
import json
from collections.abc import Iterable
from datetime import UTC, datetime
from typing import Any

Event = dict[str, Any]

# semantic-convention attribute -> normalized field
ATTRIBUTE_MAP: dict[str, str] = {
    "gen_ai.operation.name": "operation",
    "gen_ai.agent.id": "agent_id",
    "gen_ai.agent.name": "agent_name",
    "gen_ai.conversation.id": "session_id",
    "gen_ai.tool.name": "tool_name",
    "gen_ai.tool.type": "tool_type",
    "gen_ai.tool.call.id": "tool_call_id",
    "gen_ai.tool.call.arguments": "tool_args",
    "gen_ai.tool.call.result": "tool_output",
    "gen_ai.request.model": "model_id",
    "gen_ai.provider.name": "provider",
    "gen_ai.data_source.id": "data_source_id",
    "mcp.method.name": "mcp_method",
    "mcp.session.id": "mcp_session_id",
    "mcp.resource.uri": "source_uri",
    "server.address": "server_address",
    "server.port": "server_port",
}
RESOURCE_MAP = {"service.name": "service_name"}
EXTENSION_PREFIX = "abm."

# Spans whose result flows back into the agent's context.
CONTENT_OPERATIONS = {"execute_tool": "tool_output", "retrieval": "retrieval"}
CONTENT_MCP_METHODS = {"tools/call", "resources/read", "prompts/get"}
AGENT_OPERATION = "invoke_agent"


def is_otlp(obj: Any) -> bool:
    return isinstance(obj, dict) and "resourceSpans" in obj


def any_value(v: dict[str, Any] | None) -> Any:
    """Decode an OTLP/JSON AnyValue (int64 values arrive as strings)."""
    if not v:
        return None
    if "stringValue" in v:
        return v["stringValue"]
    if "boolValue" in v:
        return bool(v["boolValue"])
    if "intValue" in v:
        return int(v["intValue"])
    if "doubleValue" in v:
        return float(v["doubleValue"])
    if "arrayValue" in v:
        return [any_value(x) for x in v["arrayValue"].get("values", [])]
    if "kvlistValue" in v:
        return {kv["key"]: any_value(kv.get("value")) for kv in v["kvlistValue"].get("values", [])}
    if "bytesValue" in v:
        return base64.b64decode(v["bytesValue"]).hex()
    return None


def _attrs(items: list[dict[str, Any]] | None) -> dict[str, Any]:
    return {a["key"]: any_value(a.get("value")) for a in items or []}


def _iso(nanos: Any) -> str:
    dt = datetime.fromtimestamp(int(nanos) / 1e9, tz=UTC)
    return dt.isoformat().replace("+00:00", "Z")


def _text(v: Any) -> Any:
    """Structured tool arguments/results become JSON strings so signatures can match them."""
    return json.dumps(v, sort_keys=True, ensure_ascii=False) if isinstance(v, (dict, list)) else v


def from_otlp(docs: Iterable[dict[str, Any]], infer_context_edges: bool = True) -> list[Event]:
    """Convert OTLP/JSON trace exports to normalized events, ordered by start time.

    With `infer_context_edges`, content returned by a tool, retrieval or MCP span is linked as an
    input to every later span of the same agent (see `_infer_context_edges`).
    """
    events: list[Event] = []
    ends: dict[tuple[str, str], int] = {}
    for doc in docs:
        for rs in doc.get("resourceSpans", []):
            resource = _attrs(rs.get("resource", {}).get("attributes"))
            for ss in rs.get("scopeSpans", []):
                for span in ss.get("spans", []):
                    ev = _span_event(span, resource)
                    events.append(ev)
                    ends[(ev["trace_id"], ev["span_id"])] = int(span.get("endTimeUnixNano") or 0)
    _infer_origins(events)
    if infer_context_edges:
        _infer_context_edges(events, ends)
    events.sort(key=lambda e: (e["_start"], e["trace_id"], e["span_id"]))
    for e in events:
        del e["_start"]
    return events


def _span_event(span: dict[str, Any], resource: dict[str, Any]) -> Event:
    attrs = _attrs(span.get("attributes"))
    tid = str(span.get("traceId", "")).lower()
    ev: Event = {
        "timestamp": _iso(span.get("startTimeUnixNano") or 0),
        "trace_id": tid,
        "span_id": str(span.get("spanId", "")).lower(),
        "parent_span_id": str(span.get("parentSpanId") or "").lower() or None,
        "span_name": span.get("name"),
        "_start": int(span.get("startTimeUnixNano") or 0),
    }
    links = [str(lk.get("spanId", "")).lower() for lk in span.get("links", [])
             if str(lk.get("traceId", "")).lower() == tid and lk.get("spanId")]
    if links:
        ev["input_span_ids"] = links
    for key, fld in RESOURCE_MAP.items():
        if resource.get(key) is not None:
            ev[fld] = resource[key]
    for key, fld in ATTRIBUTE_MAP.items():
        if attrs.get(key) is not None:
            ev[fld] = _text(attrs[key]) if fld in ("tool_args", "tool_output") else attrs[key]
    if "agent_id" not in ev and "agent_name" in ev:
        ev["agent_id"] = ev["agent_name"]
    if "server_address" in ev:
        port = ev.get("server_port")
        ev["server_id"] = f"{ev['server_address']}:{port}" if port else ev["server_address"]
    for key, value in attrs.items():  # deployment extensions win over inferred values
        if key.startswith(EXTENSION_PREFIX) and value is not None:
            ev[key.removeprefix(EXTENSION_PREFIX)] = value
    return ev


def _agent_scope(ev: Event, by_id: dict[tuple[str, str], Event]) -> str | None:
    """Nearest invoke_agent ancestor (excluding the span itself), None for the trace root scope."""
    seen: set[str] = set()
    parent = ev.get("parent_span_id")
    while parent and parent not in seen:
        seen.add(parent)
        p = by_id.get((ev["trace_id"], parent))
        if p is None:
            return None
        if p.get("operation") == AGENT_OPERATION:
            return parent
        parent = p.get("parent_span_id")
    return None


def _infer_origins(events: list[Event]) -> None:
    by_id = {(e["trace_id"], e["span_id"]): e for e in events}
    for ev in events:
        if ev.get("input_origin"):
            continue
        op = ev.get("operation")
        if op in CONTENT_OPERATIONS:
            ev["input_origin"] = CONTENT_OPERATIONS[op]
        elif ev.get("mcp_method") in CONTENT_MCP_METHODS:
            ev["input_origin"] = "tool_output"
        elif op == AGENT_OPERATION and _agent_scope(ev, by_id) is None:
            ev["input_origin"] = "user"  # the outermost agent receives the user's request


def _infer_context_edges(events: list[Event], ends: dict[tuple[str, str], int]) -> None:
    """GenAI instrumentations record a tool call as a child of the agent span, a sibling of the model
    turn that reads its result, so parent edges never connect a tool result to the next step. The
    result returns to the agent's context, which every later step of that agent sees: link each
    content span (tool_output / retrieval / memory origin) as an input of every span in the same
    agent scope that starts after it ends. Taint inside a sub-agent does not flow back to the calling
    agent unless the instrumentation records a span link."""
    by_id = {(e["trace_id"], e["span_id"]): e for e in events}
    scope = {k: _agent_scope(e, by_id) for k, e in by_id.items()}
    content = [k for k, e in by_id.items() if e.get("input_origin") in ("tool_output", "retrieval", "memory")]
    for ck in content:
        end = ends.get(ck, 0)
        for k, ev in by_id.items():
            if k == ck or k[0] != ck[0] or scope[k] != scope[ck] or ev["_start"] < end:
                continue
            inputs = ev.setdefault("input_span_ids", [])
            if ck[1] not in inputs:
                inputs.append(ck[1])
