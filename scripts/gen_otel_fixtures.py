"""Deterministically (re)generate OTLP/JSON trace fixtures under tests/fixtures/otel/.

    python scripts/gen_otel_fixtures.py

Shaped like GenAI semantic-convention instrumentation: every model turn and tool call is a child of
the invoke_agent span, tool results are siblings of the turns that read them, and there are no span
links. Detection therefore depends on the adapter's context-edge inference (abm.otel). Trust and
tool impact ride along as `abm.*` attributes, as a Collector transform processor would add them.

    ag016_otlp_attack.json    one pretty-printed ExportTraceServiceRequest; web content is untrusted
    ag016_otlp_benign.jsonl   same run, trusted intranet content, written the way the Collector file
                              exporter does (one request per line, the trace split across two lines)
"""

from __future__ import annotations

import json
from pathlib import Path

OUT = Path(__file__).resolve().parents[1] / "tests" / "fixtures" / "otel"
T0 = 1_790_863_200_000_000_000  # 2026-10-01T14:00:00Z in ns
S = 1_000_000_000


def attr(key: str, value) -> dict:
    if isinstance(value, bool):
        v = {"boolValue": value}
    elif isinstance(value, int):
        v = {"intValue": str(value)}  # OTLP/JSON encodes int64 as a string
    elif isinstance(value, float):
        v = {"doubleValue": value}
    elif isinstance(value, dict):
        v = {"kvlistValue": {"values": [attr(k, x) for k, x in value.items()]}}
    else:
        v = {"stringValue": str(value)}
    return {"key": key, "value": v}


def span_id(trace_id: str, n: int) -> str:
    return f"{trace_id[:12]}{n:04x}"


def span(trace_id: str, n: int, parent: int | None, name: str, start: float, end: float,
         kind: int = 1, **attrs) -> dict:
    return {
        "traceId": trace_id, "spanId": span_id(trace_id, n),
        "parentSpanId": span_id(trace_id, parent) if parent else "",
        "name": name, "kind": kind,
        "startTimeUnixNano": str(T0 + int(start * S)), "endTimeUnixNano": str(T0 + int(end * S)),
        "attributes": [attr(k.replace("__", "."), v) for k, v in attrs.items()],
        "status": {},
    }


def run(trace_id: str, page: str, trust: str) -> list[dict]:
    agent = {"gen_ai__agent__id": "ap-agent", "gen_ai__conversation__id": f"s-{trace_id[:4]}"}
    return [
        span(trace_id, 1, None, "invoke_agent ap-agent", 0, 10, gen_ai__operation__name="invoke_agent",
             gen_ai__agent__name="AP assistant", **agent),
        span(trace_id, 2, 1, "chat gpt-4o", 0.1, 1.0, kind=3, gen_ai__operation__name="chat",
             gen_ai__request__model="gpt-4o", gen_ai__provider__name="openai", **agent),
        span(trace_id, 3, 1, "execute_tool web.fetch", 1.1, 2.0, gen_ai__operation__name="execute_tool",
             gen_ai__tool__name="web.fetch", gen_ai__tool__type="function", gen_ai__tool__call__id="call_1",
             gen_ai__tool__call__arguments={"url": page}, abm__tool_class="read", abm__source_trust=trust,
             **agent),
        span(trace_id, 4, 1, "chat gpt-4o", 2.1, 3.0, kind=3, gen_ai__operation__name="chat",
             gen_ai__request__model="gpt-4o", gen_ai__provider__name="openai", **agent),
        span(trace_id, 5, 1, "execute_tool payments.create_transfer", 3.1, 4.0,
             gen_ai__operation__name="execute_tool", gen_ai__tool__name="payments.create_transfer",
             gen_ai__tool__type="extension", gen_ai__tool__call__id="call_2",
             gen_ai__tool__call__arguments={"amount": 9800, "currency": "EUR"}, abm__tool_class="privileged",
             **agent),
        span(trace_id, 6, 5, "tools/call payments.create_transfer", 3.2, 3.9, kind=3,
             mcp__method__name="tools/call", mcp__session__id="mcp-s-1", gen_ai__operation__name="execute_tool",
             gen_ai__tool__name="payments.create_transfer", server__address="mcp-finance.internal",
             server__port=443, abm__tool_class="privileged", **agent),
    ]


def export(spans: list[dict]) -> dict:
    return {"resourceSpans": [{
        "resource": {"attributes": [attr("service.name", "ap-agent-svc")]},
        "scopeSpans": [{"scope": {"name": "agent-framework"}, "spans": spans}],
    }]}


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    attack = run("0af7651916cd43dd8448eb211c80319c", "https://supplier-portal.example/invoice/7781", "untrusted")
    (OUT / "ag016_otlp_attack.json").write_text(json.dumps(export(attack), indent=2) + "\n", encoding="utf-8")
    benign = run("1bf8762a27de54ee9559fc322d91420d", "https://intranet.example/finance/payment-runbook",
                 "trusted")
    lines = [export(benign[:3]), export(benign[3:])]
    (OUT / "ag016_otlp_benign.jsonl").write_text(
        "".join(json.dumps(x, separators=(",", ":")) + "\n" for x in lines), encoding="utf-8")
    print(f"wrote {OUT.relative_to(OUT.parents[2])}: ag016_otlp_attack.json, ag016_otlp_benign.jsonl")


if __name__ == "__main__":
    main()
