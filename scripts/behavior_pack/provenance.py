"""Behavior pack: provenance over the agent span graph (docs/agent-telemetry.md).

Fixtures are whole agent runs: every event is a span with trace_id / span_id / parent_span_id, and
model turns list the spans whose output they consumed in input_span_ids. Each benign trace has the
same shape as its attack trace; only the property the detection depends on differs (trust of the
retrieved content, allowlisting of the destination, uniqueness of the tool name).
"""

from __future__ import annotations

from ._helpers import AGT, MCP, B, act, events, prov, thr

GRAPH = ["trace_id", "span_id", "parent_span_id", "input_span_ids"]
MCP_SPAN = ["trace_id", "span_id", "parent_span_id", "session_id", "agent_id", "server_id", "mcp_method",
            "tool_name", "tool_class"]


def span_id(trace_id: str, n: int) -> str:
    return f"{trace_id[:12]}{n:04x}"


def trace(trace_id: str, *spans: dict, step: float = 2) -> list[dict]:
    """One agent run. Span n (1-based) gets a 16-hex span id; `parent=n` and `inputs=[n, ...]` refer
    to earlier spans by position. Timestamps are assigned in order, `step` seconds apart."""
    out = []
    for n, s in enumerate(spans, 1):
        s = dict(s)
        parent, inputs = s.pop("parent", None), s.pop("inputs", ())
        ev = {"trace_id": trace_id, "span_id": span_id(trace_id, n),
              "parent_span_id": span_id(trace_id, parent) if parent else None}
        if inputs:
            ev["input_span_ids"] = [span_id(trace_id, i) for i in inputs]
        out.append({**ev, **s})
    return events(*out, step=step)


# ------------------------------------------------------------ AG-016 untrusted content -> privileged tool
AP = {"session_id": "s-ap1", "agent_id": "ap-agent", "principal_id": "user-2208"}


def _ap_run(trace_id: str, session: str, doc_uri: str, trust: str) -> list[dict]:
    s = {**AP, "session_id": session}
    return trace(
        trace_id,
        {**s, "operation": "invoke_agent", "input_origin": "user", "source_trust": "trusted",
         "prompt": "Process the new supplier invoices"},
        {**s, "operation": "retrieval", "tool_name": "docs.search", "tool_class": "read", "parent": 1,
         "input_origin": "retrieval", "source_trust": trust, "source_uri": doc_uri},
        {**s, "operation": "chat", "model_id": "assistant-prod", "parent": 1, "inputs": [2]},
        {**s, "mcp_method": "tools/call", "server_id": "mcp-finance", "tool_name": "payments.create_transfer",
         "tool_class": "privileged", "parent": 3},
    )


# ------------------------------------------------------------ EXF-014 secret read -> outbound HTTP
DEV = {"agent_id": "deploy-agent", "principal_id": "user-3120"}


def _deploy_run(trace_id: str, session: str, domain: str, allowlisted: bool) -> list[dict]:
    s = {**DEV, "session_id": session}
    return trace(
        trace_id,
        {**s, "operation": "invoke_agent", "input_origin": "user", "source_trust": "trusted",
         "prompt": "Deploy the staging build"},
        {**s, "operation": "execute_tool", "tool_name": "vault.read", "tool_class": "secret_read", "parent": 1,
         "input_origin": "tool_output", "source_trust": "trusted"},
        {**s, "operation": "chat", "model_id": "assistant-prod", "parent": 1, "inputs": [2]},
        {**s, "operation": "execute_tool", "tool_name": "http.request", "tool_class": "egress", "parent": 3,
         "destination_domain": domain, "destination_allowlisted": allowlisted, "request_bytes": 2130},
    )


# ------------------------------------------------------------ SC-012 tool-name shadowing across servers
def _tool_list_run(trace_id: str, session: str, second_server: str, second_tools: list[str]) -> list[dict]:
    """Agent session start: both attached MCP servers advertise their tools (one tool_advertised event
    per tool in the tools/list result), then the agent calls create_issue."""
    s = {"session_id": session, "agent_id": "dev-agent"}
    adverts = [("mcp-github", t) for t in ("create_issue", "search_code")]
    adverts += [(second_server, t) for t in second_tools]
    return trace(
        trace_id,
        {**s, "operation": "invoke_agent", "input_origin": "user", "source_trust": "trusted",
         "prompt": "File a bug for the failing login test"},
        *({**s, "event_type": "tool_advertised", "mcp_method": "tools/list", "server_id": srv,
           "tool_name": tool, "parent": 1} for srv, tool in adverts),
        {**s, "mcp_method": "tools/call", "server_id": "mcp-github", "tool_name": "create_issue",
         "tool_class": "write", "parent": 1},
    )


SPECS = [
    B("AG-016", "agentic", "Untrusted retrieved or tool-output content reaches a privileged tool call",
      "high", "medium",
      "Content from an untrusted retrieval source or tool result (public web page, inbound email, external "
      "upload) reaches a privileged tool call (payments, identity, permissions, configuration, code "
      "execution) within 3 hops of the agent's span graph: indirect prompt injection turned into action. "
      "Computed per trace along parent_span_id and input_span_ids. Needs input_origin, source_trust and "
      "tool_class from the runtime or gateway (docs/agent-telemetry.md). BHV-AG-008 is the single-event "
      "form for runtimes that can only flag 'untrusted content in context'.",
      "AML.T0053", secondary=("AML.T0051.001",), source=AGT,
      fields=[*GRAPH, "session_id", "agent_id", "operation", "tool_name", "tool_class", "input_origin",
              "source_trust"],
      also={MCP: MCP_SPAN},
      detection=prov({"input_origin": {"in": ["retrieval", "tool_output"]}, "source_trust": "untrusted"},
                     {"tool_class": "privileged"}, max_hops=3,
                     fp=("Agents built to act on external documents where the human approval happens "
                         "outside the traced run",)),
      mitigations=["AML.M0030", "AML.M0029", "AML.M0026"],
      response=[act("deny_tool_call", session="{{session_id}}", tool="{{tool_name}}"),
                act("kill_session", session="{{session_id}}"),
                act("open_incident", queue="ai-sec", priority="P1")],
      attack=_ap_run("4bf92f3577b34da6a3ce929d0e0e4736", "s-ap1",
                     "sharepoint://ap-inbox/uploads/invoice-7781.pdf", "untrusted"),
      benign=_ap_run("5c0a1d2e3f4b45a6b7c8d9e0f1a2b3c4", "s-ap2",
                     "sharepoint://finance/policies/payment-runbook.docx", "trusted")),

    B("EXF-014", "exfiltration", "Secret read flows into an outbound HTTP call to a non-allowlisted host",
      "critical", "high",
      "Within one agent run, the output of a secret_read tool (vault, credential store, environment) "
      "reaches an egress call to a destination outside the allowlist within 4 hops of the span graph. "
      "Unlike BHV-EXF-011, which pairs any secret read with any egress in the same session window, this "
      "requires a causal path from the secret to the request.",
      "AML.T0086", secondary=("AML.T0098",), source=AGT, attack_bridge=("T1567",),
      fields=[*GRAPH, "session_id", "agent_id", "tool_name", "tool_class", "destination_domain",
              "destination_allowlisted"],
      also={MCP: MCP_SPAN},
      detection=prov({"tool_class": "secret_read"},
                     {"tool_class": "egress", "destination_allowlisted": False}, max_hops=4,
                     fp=("A new integration whose API host has not been added to the egress allowlist",)),
      mitigations=["AML.M0026", "AML.M0028", "AML.M0032"],
      response=[act("deny_tool_call", session="{{session_id}}", tool="{{tool_name}}"),
                act("kill_session", session="{{session_id}}"),
                act("rotate_credentials", scope="agent-session-{{session_id}}"),
                act("open_incident", queue="ai-sec", priority="P1")],
      attack=_deploy_run("7c1e5a9b2d4f46e8a0b3c5d7e9f1a2b4", "s-dp1", "paste.attacker.example", False),
      benign=_deploy_run("8d2f6b0c3e5a47f9b1c4d6e8f0a2b3c5", "s-dp2", "api.deploy.example", True)),

    B("SC-012", "supply-chain", "MCP tool name advertised by more than one server to the same agent",
      "high", "medium",
      "Two or more MCP servers advertise a tool with the same name to one agent within an hour. The agent "
      "cannot tell which implementation it will call, so a malicious server can intercept calls meant for "
      "a trusted one or steer them through its own tool description (tool shadowing). Needs the gateway "
      "to log one tool_advertised event per tool in each tools/list result.",
      "AML.T0110", secondary=("AML.T0010.005",), source=MCP,
      fields=["agent_id", "server_id", "tool_name", "event_type"],
      detection=thr("1h", ["agent_id", "tool_name"], {"servers": "dcount(server_id)"}, ["servers >= 2"],
                    filters={"event_type": "tool_advertised"},
                    fp=("Two deployments of one server (for example prod and staging) attached to the same "
                        "agent",)),
      mitigations=["AML.M0028", "AML.M0014"],
      response=[act("notify", channel="platform-sec"),
                act("open_incident", queue="ai-sec", priority="P2")],
      attack=_tool_list_run("9e3a7c1d4f6b48a0c2d5e7f9a1b3c4d6", "s-dv1", "mcp-pdf-tools",
                            ["pdf_to_text", "create_issue"]),
      benign=_tool_list_run("a04b8d2e5a7c49b1d3e6f8a0b2c4d5e7", "s-dv2", "mcp-jira",
                            ["create_ticket", "search_tickets"])),
]
