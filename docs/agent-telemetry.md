# Agent Telemetry Contract (agent_runtime, mcp_gateway)

Provenance detections follow content through an agent run: from the step where untrusted content
entered the agent's context to the step where the agent acted on it. That needs every
`agent_runtime` and `mcp_gateway` event to be a **span**, one step of the run (a model turn, a tool
call, a retrieval, an MCP request), linked to the steps around it.

The contract is `AgentSpan` in `src/abm/telemetry.py`; `make schema` exports it to
`schemas/agent-span.schema.json`. Source-specific fields (`tool_name`, `tool_args`, `server_id`, ...)
stay as they are; the contract adds the fields below.

## Span fields

| Field | Required | Meaning |
|---|---|---|
| `trace_id` | yes | One agent run, from the user's request to the final answer. Use the OpenTelemetry trace id when there is one. |
| `span_id` | yes | This step. Unique within the trace. |
| `parent_span_id` | yes (null at the root) | The step that **caused** this one. For a tool call, the model turn that requested it. |
| `input_span_ids` | no | Steps whose **output this step consumed**, e.g. the tool results and retrieved chunks fed into a model turn. Maps to OpenTelemetry span links. |
| `input_origin` | when the step brings content in | Origin of the content this step brought into the agent's context: `user`, `tool_output`, `retrieval`, `memory`. Empty for steps that only act on existing context (model turns, outbound calls). |
| `source_trust` | with `input_origin` | `trusted` or `untrusted`: internal KB vs public web, verified vs unverified MCP server, internal mailbox vs inbound external mail. |
| `tool_class` | on tool calls | Impact class from the tool registry (below). |

`parent_span_id` and `input_span_ids` are different relationships. A model turn is usually caused by
the agent loop (parent), but it reads the results of earlier tool calls (inputs). Producers that
only know the call tree can leave `input_span_ids` out. Their spans still form a graph, but content
then only flows down the call tree.

### Tool classes

| `tool_class` | Use for |
|---|---|
| `read` | Lookups with no side effects (search, fetch, list) |
| `write` | Changes data inside the tenant (tickets, documents, records) |
| `privileged` | Payments, identity and permission changes, configuration, code or command execution |
| `secret_read` | Returns credentials or secrets (vault, credential store, environment) |
| `egress` | Sends data outside the organization (HTTP to external hosts, external email, webhooks) |

### mcp_gateway specifics

- `tools/call`, `resources/read` and `prompts/get` requests are spans. Set `mcp_method`,
  `server_id`, `tool_name` and `tool_class`. When the gateway sees a call the agent runtime also
  logs, reuse the runtime's span as `parent_span_id`. If both report the same `span_id`, the engine
  merges them.
- A `tools/list` result is logged as one `event_type: tool_advertised` event per advertised tool
  (`agent_id`, `server_id`, `tool_name`). BHV-SC-013 (tool shadowing) counts servers per tool name
  from these events.

## How provenance logic uses the graph

`src/abm/provenance.py` groups spans by `trace_id`. Inside each trace it adds an edge
`parent -> span` for `parent_span_id` and `input -> span` for each id in `input_span_ids`, then
spreads taint from every span matching the behavior's `source` spec:

- Distance is the shortest path in edges from any source. A sink matching `sink` alerts when
  reached within `max_hops` (1 to 8).
- A source never reaches itself: a span's own output cannot have caused its own invocation. A source
  reached from another source is an ordinary reached span.
- One action often appears as nested spans (the agent's `execute_tool` span and the MCP client span
  under it). A reached sink whose parent chain holds another reached sink is folded into the
  outermost one and listed in the alert evidence.
- `filters` scope the events before the graph is built.
- Malformed traces are evaluated as far as they go: edges to spans missing from the trace are
  dropped, duplicate span ids are merged, cycles are reported. The first three issues appear in
  the alert evidence as `graph: ...`.

Alerts carry the sink span's fields plus `trace_id`, `span_id` (the sink), `source_span_id` and
`hops`, and the evidence shows the path with edge kinds, e.g.
`a2(docs.search) -input-> a3(chat) -parent-> a4(payments.create_transfer) (2 hop(s))`.

```yaml
detection:
  logic: provenance
  provenance:
    source: { input_origin: { in: [retrieval, tool_output] }, source_trust: untrusted }
    sink:   { tool_class: privileged }
    max_hops: 3
```

## OpenTelemetry input

`abm replay` and fixture tests accept OTLP/JSON trace exports: a single `ExportTraceServiceRequest`
document (`{"resourceSpans": [...]}`), or one per line as the Collector `file` exporter writes them.
They may be mixed with normalized events in one file. `src/abm/otel.py` converts them.

**Conventions checked.** Checked against `opentelemetry-semantic-conventions` 0.66b1 (semconv 1.44.0).
There, every `gen_ai.*` and `mcp.*` attribute is marked *moved to
[open-telemetry/semantic-conventions-genai](https://github.com/open-telemetry/semantic-conventions-genai)*,
with the names unchanged. The definitions used here come from 0.64b0 (semconv 1.41.1), the last
release that ships them in full. The GenAI conventions are in Development status, so recheck this
mapping when upgrading instrumentation.

| OpenTelemetry | Normalized field |
|---|---|
| `traceId`, `spanId`, `parentSpanId` (hex) | `trace_id`, `span_id`, `parent_span_id` |
| span links in the same trace | `input_span_ids` |
| `startTimeUnixNano` | `timestamp` |
| `gen_ai.operation.name` (`invoke_agent`, `chat`, `execute_tool`, `retrieval`, ...) | `operation` |
| `gen_ai.agent.id` (else `gen_ai.agent.name`) | `agent_id` |
| `gen_ai.conversation.id` | `session_id` |
| `gen_ai.tool.name`, `.type`, `.call.id` | `tool_name`, `tool_type`, `tool_call_id` |
| `gen_ai.tool.call.arguments`, `.call.result` | `tool_args`, `tool_output` (JSON text if structured) |
| `gen_ai.request.model`, `gen_ai.provider.name`, `gen_ai.data_source.id` | `model_id`, `provider`, `data_source_id` |
| `mcp.method.name`, `mcp.session.id`, `mcp.resource.uri` | `mcp_method`, `mcp_session_id`, `source_uri` |
| `server.address` + `server.port` | `server_id` |
| resource `service.name` | `service_name` |
| `abm.<field>` (deployment extension) | `<field>`; overrides anything inferred |

**Not in the conventions.** Trust, tool impact and memory reads have no semantic-convention
attributes. Add `abm.source_trust`, `abm.tool_class` and, where needed, `abm.input_origin` or
`abm.server_id` in the pipeline. A Collector `transform` processor fed from the tool registry is a
natural place. For example (OTTL, adjust to your registry):

```yaml
processors:
  transform/abm:
    trace_statements:
      - context: span
        statements:
          - set(attributes["abm.tool_class"], "privileged") where attributes["gen_ai.tool.name"] == "payments.create_transfer"
          - set(attributes["abm.source_trust"], "untrusted") where attributes["gen_ai.tool.name"] == "web.fetch"
```

**Inferred when absent.**

- `input_origin`: `execute_tool` spans and MCP `tools/call`, `resources/read` and `prompts/get`
  spans are `tool_output`. `retrieval` spans are `retrieval`. The outermost `invoke_agent` span is
  `user`.
- **Context edges.** GenAI instrumentations make each tool call a child of the agent span and a
  sibling of the model turn that reads its result, so parent edges never connect a tool result to
  the next step. The result returns to the agent's context, which every later step of that agent
  sees. The adapter therefore links each content span (`tool_output`, `retrieval` or `memory`
  origin) as an input of every span under the same nearest `invoke_agent` ancestor that starts after
  the content span ends. `from_otlp(..., infer_context_edges=False)` turns this off.

## Limits

- **Compiled KQL.** The rule unions the declared sources' tables, builds an edge table from
  `ParentSpanId` and `InputSpanIds` (optional column), and unrolls `max_hops` joins. It differs from
  the engine in four ways:
  - Only spans inside the rule's query period are joined.
  - Duplicate span rows are not merged.
  - Nested sinks are not folded, so one action can produce two result rows.
  - Context edges are not inferred. If spans reach Sentinel straight from OpenTelemetry
    instrumentation, `InputSpanIds` is empty and the rule follows parent chains only, which misses
    the usual sibling pattern. Populate `InputSpanIds` at ingestion (links, or the same inference as
    `abm.otel`) before relying on the rule.
- **Sigma and SPL.** They get a stub with no rule and `abm compile` logs a warning. Sigma cannot
  follow span edges. In SPL an unrolled join is bounded by join and subsearch result limits and
  truncates without an error, so it would under-report silently.
- **Sub-agents.** Taint inside a sub-agent does not flow back to the calling agent unless the
  instrumentation records a span link from the sub-agent's result.
- **Parallel tool calls.** When one turn issues several calls at once, context edges are
  conservative: a call that finished first is treated as visible to the ones still starting.
- **Trust is an input, not an output.** Detections are as good as `source_trust` and `tool_class`.
  A trusted source that serves attacker-controlled content (a shared drive anyone can upload to) must
  be marked untrusted.
