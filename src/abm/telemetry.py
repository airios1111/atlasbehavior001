"""Telemetry contract for traced agent sources (agent_runtime, mcp_gateway).

Every agent_runtime and mcp_gateway event that takes part in a provenance detection is a *span*:
one step of an agent run (a model turn, a tool call, a retrieval, an MCP request). The fields below
let the engine rebuild the run as a per-trace graph and follow untrusted content through it.
See docs/agent-telemetry.md for producer guidance and the OpenTelemetry mapping.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError

TRACED_SOURCES = ("agent_runtime", "mcp_gateway")

# Fields a provenance behavior must declare in telemetry.required.
GRAPH_FIELDS = ("trace_id", "span_id", "parent_span_id")

# Where the content that entered the agent's context at this span came from.
INPUT_ORIGINS = ("user", "tool_output", "retrieval", "memory")

# Impact class of the tool a span invokes, assigned by the runtime/gateway from its tool registry.
TOOL_CLASSES = ("read", "write", "privileged", "secret_read", "egress")

InputOrigin = Literal["user", "tool_output", "retrieval", "memory"]
ToolClass = Literal["read", "write", "privileged", "secret_read", "egress"]


class AgentSpan(BaseModel):
    """One traced agent_runtime / mcp_gateway event. Source-specific fields (tool_name, server_id,
    tool_args, ...) are allowed alongside; only the provenance fields are constrained here."""

    model_config = ConfigDict(extra="allow")

    timestamp: str | float = Field(description="Span start, ISO-8601 or epoch seconds")
    trace_id: str = Field(min_length=1, description="One agent run; OpenTelemetry trace id when available")
    span_id: str = Field(min_length=1, description="This step; unique within the trace")
    parent_span_id: str | None = Field(
        description="Required, null at the root. The step that caused this one (for a tool call: the model turn that requested it). "
                    "Null for the root span.")
    input_span_ids: list[str] = Field(
        default_factory=list,
        description="Steps whose output this step consumed (data-flow edges, e.g. the tool results fed "
                    "into a model turn). Maps to OpenTelemetry span links.")
    input_origin: InputOrigin | None = Field(
        default=None,
        description="Origin of the content this step brought into the agent's context: user (a user "
                    "turn), tool_output (a tool or MCP result), retrieval (RAG/search results), memory "
                    "(long-term memory read). Null for steps that only act on existing context.")
    source_trust: Literal["trusted", "untrusted"] | None = Field(
        default=None,
        description="Trust of the content's origin (internal KB vs public web, verified vs unverified "
                    "MCP server). Set when input_origin is set.")
    tool_class: ToolClass | None = Field(
        default=None,
        description="Impact class of the invoked tool: read, write, privileged (payments, identity, "
                    "permissions, config, code execution), secret_read (returns credentials), egress "
                    "(sends data outside the organization).")


def check_span(ev: dict[str, Any]) -> list[str]:
    """Contract violations for one event; empty when it conforms."""
    try:
        AgentSpan.model_validate(ev)
    except ValidationError as e:
        return [f"{'.'.join(str(x) for x in err['loc']) or '<root>'}: {err['msg']}" for err in e.errors()]
    return []
