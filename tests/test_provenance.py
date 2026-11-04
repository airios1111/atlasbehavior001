"""Provenance graph, taint propagation, the agent telemetry contract, OTLP input and compilers."""

import copy
import json
import logging

import pytest
import yaml
from pydantic import ValidationError

from abm.cli import main
from abm.compilers import TARGETS
from abm.compilers.common import is_stub
from abm.engine import Engine, load_events
from abm.models import Behavior
from abm.otel import any_value, from_otlp
from abm.provenance import build_graphs, find, propagate
from abm.telemetry import check_span
from abm.validator import validate

PROVENANCE_IDS = ["BHV-AG-016", "BHV-EXF-014"]
T = "t" * 32


def sp(sid, parent=None, inputs=(), ts=0, trace=T, **fields):
    ev = {"timestamp": f"2026-10-01T14:00:{ts:02d}Z", "trace_id": trace, "span_id": sid,
          "parent_span_id": parent, **fields}
    if inputs:
        ev["input_span_ids"] = list(inputs)
    return ev


def untrusted(e):
    return e.get("source_trust") == "untrusted"


def privileged(e):
    return e.get("tool_class") == "privileged"


def chain(n, **sink_fields):
    """root -> s1 (untrusted retrieval) -> s2 -> ... -> s{n} (privileged): n-1 hops source to sink."""
    evs = [sp("root"), sp("s1", "root", ts=1, input_origin="retrieval", source_trust="untrusted")]
    for i in range(2, n + 1):
        evs.append(sp(f"s{i}", f"s{i - 1}", ts=i))
    evs[-1].update(tool_class="privileged", **sink_fields)
    return evs


# ---------------------------------------------------------------- model + validation
BASE = {
    "id": "BHV-AG-099", "name": "x", "status": "experimental", "severity": "low", "confidence": "low",
    "description": "x",
    "atlas": {"tactics": ["AML.TA0005"], "techniques": [{"id": "AML.T0053"}]},
    "telemetry": {"required": [{"source": "agent_runtime",
                                "fields": ["timestamp", "trace_id", "span_id", "parent_span_id"]}]},
    "detection": {"logic": "provenance", "provenance": {
        "source": {"source_trust": "untrusted"}, "sink": {"tool_class": "privileged"}, "max_hops": 3}},
}


def make(**detection):
    d = copy.deepcopy(BASE)
    d["detection"].update(detection)
    return Behavior.model_validate(d)


def test_provenance_model_valid():
    assert make().detection.provenance.max_hops == 3


@pytest.mark.parametrize("detection,message", [
    ({"provenance": None}, "requires 'provenance'"),
    ({"logic": "field_match", "match": {"a": 1}}, "requires logic: provenance"),
    ({"window": "1h"}, "'window' does not apply"),
    ({"provenance": {"source": {"a": {"regexp": "x"}}, "sink": {"b": 1}, "max_hops": 2}}, "unknown operator"),
    ({"provenance": {"source": {"a": {"regex": "("}}, "sink": {"b": 1}, "max_hops": 2}}, "invalid regex"),
    ({"provenance": {"source": {"a": {"in": "x"}}, "sink": {"b": 1}, "max_hops": 2}}, "takes a list"),
    ({"provenance": {"source": {}, "sink": {"b": 1}, "max_hops": 2}}, "at least 1"),
    ({"provenance": {"source": {"a": 1}, "sink": {"b": 1}, "max_hops": 0}}, "greater than or equal to 1"),
    ({"provenance": {"source": {"a": 1}, "sink": {"b": 1}, "max_hops": 9}}, "less than or equal to 8"),
])
def test_provenance_model_rejects(detection, message):
    with pytest.raises(ValidationError, match=message):
        make(**detection)


def test_validator_requires_graph_fields(root, catalog):
    from abm.loader import LoadResult

    b = make()
    b = b.model_copy(update={"telemetry": b.telemetry.model_copy(update={"required": [
        b.telemetry.required[0].model_copy(update={"fields": ["timestamp", "trace_id"]})]})})
    errs = [f.message for f in validate(LoadResult([b]), catalog, root) if f.level == "error"]
    assert any("['span_id', 'parent_span_id']" in m for m in errs)


# ---------------------------------------------------------------- graph
def test_graph_edges_parent_and_input():
    g = build_graphs([sp("a"), sp("b", "a"), sp("c", "a", inputs=["b"])])[T]
    assert g.edges == {"a": [("b", "parent"), ("c", "parent")], "b": [("c", "input")]}
    assert g.issues == []


def test_graph_reports_missing_self_duplicate_and_cycle():
    g = build_graphs([
        sp("a", "ghost"),                        # parent outside the trace
        sp("b", "a", inputs=["b"]),              # self reference
        sp("c", "a"), sp("c", "b", tool_name="x"),  # duplicate with conflicting parent
        sp("d", "e"), sp("e", "d"),              # cycle
    ])[T]
    text = " | ".join(g.issues)
    assert "not in trace" in text and "ghost" in text
    assert "references itself" in text
    assert "conflicting parent_span_id" in text and g.spans["c"]["parent_span_id"] == "a"
    assert g.spans["c"]["tool_name"] == "x"       # later report fills gaps
    assert "cycle among spans d, e" in text
    assert propagate(g, lambda e: e["span_id"] == "d", 8)["e"].hops == 1  # terminates on cycles


def test_events_without_trace_fields_are_ignored_and_traces_are_isolated():
    evs = [{"timestamp": "2026-10-01T14:00:00Z", "tool_class": "privileged"},
           *chain(3)[:2], sp("s2", "s1", trace="u" * 32, tool_class="privileged")]
    assert set(build_graphs(evs)) == {T, "u" * 32}
    assert find(evs, untrusted, privileged, 8) == []  # same span ids, different trace: no edge


def test_contract_violation_is_reported():
    g = build_graphs([sp("a", input_origin="web")])[T]
    assert any("input_origin" in i for i in g.issues)


# ---------------------------------------------------------------- taint
@pytest.mark.parametrize("length,max_hops,alerts", [(4, 3, 1), (4, 2, 0), (2, 1, 1), (9, 8, 1), (10, 8, 0)])
def test_max_hops_boundary(length, max_hops, alerts):
    findings = find(chain(length), untrusted, privileged, max_hops)
    assert len(findings) == alerts
    if alerts:
        assert findings[0].reach.hops == length - 1


def test_shortest_path_wins():
    evs = chain(4)
    evs[-1]["input_span_ids"] = ["s1"]  # shortcut s1 -input-> s4
    [f] = find(evs, untrusted, privileged, 3)
    assert f.reach.hops == 1 and [k for _, k in f.reach.path] == ["", "input"]


def test_source_does_not_taint_itself_but_other_sources_do():
    alone = [sp("a", input_origin="tool_output", source_trust="untrusted", tool_class="privileged")]
    assert find(alone, untrusted, privileged, 3) == []
    pair = [sp("a", source_trust="untrusted"),
            sp("b", "a", ts=1, source_trust="untrusted", tool_class="privileged")]
    [f] = find(pair, untrusted, privileged, 3)
    assert (f.sink_id, f.reach.source, f.reach.hops) == ("b", "a", 1)


def test_nested_sinks_fold_into_outermost():
    evs = chain(3)
    evs.append(sp("mcp", "s3", ts=9, tool_class="privileged"))  # MCP client span under the agent's call
    [f] = find(evs, untrusted, privileged, 3)
    assert f.sink_id == "s3" and f.nested == ["mcp"]
    assert "nested sink span(s) mcp" in f.describe()


# ---------------------------------------------------------------- engine + fixtures
def test_provenance_alert_context_and_evidence(behaviors, root):
    b = behaviors["BHV-AG-016"]
    [a] = Engine([b]).evaluate(b, load_events(root / "tests/fixtures/pack/ag016_attack.jsonl"))
    assert a.context["trace_id"] == "4bf92f3577b34da6a3ce929d0e0e4736"
    assert a.context["span_id"] == "4bf92f3577b30004" and a.context["source_span_id"] == "4bf92f3577b30002"
    assert a.context["tool_name"] == "payments.create_transfer" and a.metrics == {"hops": 2}
    assert a.evidence[0] == ("path 4bf92f3577b30002(docs.search) -input-> 4bf92f3577b30003(chat) "
                             "-parent-> 4bf92f3577b30004(payments.create_transfer) (2 hop(s))")


def test_filters_scope_the_graph(behaviors, root):
    b = behaviors["BHV-AG-016"]
    d = b.detection.model_copy(update={"filters": {"agent_id": {"ne": "ap-agent"}}})
    scoped = b.model_copy(update={"detection": d})
    assert Engine([scoped]).evaluate(scoped, load_events(root / "tests/fixtures/pack/ag016_attack.jsonl")) == []


@pytest.mark.parametrize("stem", ["ag016", "exf014", "sc012"])
def test_trace_fixtures_follow_the_contract(root, stem):
    for kind in ("attack", "benign"):
        evs = load_events(root / f"tests/fixtures/pack/{stem}_{kind}.jsonl")
        assert len({e["trace_id"] for e in evs}) == 1 and len(evs) >= 4  # one multi-event run
        assert [p for e in evs for p in check_span(e)] == []
        assert build_graphs(evs)[evs[0]["trace_id"]].issues == []


@pytest.mark.parametrize("stem", ["ag016", "exf014", "sc012"])
def test_benign_twin_has_the_same_shape(root, stem):
    def shape(kind):
        evs = load_events(root / f"tests/fixtures/pack/{stem}_{kind}.jsonl")
        g = build_graphs(evs)[evs[0]["trace_id"]]
        idx = {sid: i for i, sid in enumerate(g.spans)}
        return sorted((idx[a], idx[b], k) for a, outs in g.edges.items() for b, k in outs), \
            [sorted(e) for e in evs]

    assert shape("attack") == shape("benign")


# ---------------------------------------------------------------- OpenTelemetry input
def test_any_value_decoding():
    assert any_value({"intValue": "42"}) == 42
    assert any_value({"kvlistValue": {"values": [{"key": "a", "value": {"boolValue": True}}]}}) == {"a": True}
    assert any_value({"arrayValue": {"values": [{"stringValue": "x"}, {"doubleValue": 1.5}]}}) == ["x", 1.5]
    assert any_value({"bytesValue": "AQI="}) == "0102"


def test_otlp_fixtures_alert_and_benign_twin_does_not(behaviors, root):
    b = behaviors["BHV-AG-016"]
    attack = load_events(root / "tests/fixtures/otel/ag016_otlp_attack.json")
    benign = load_events(root / "tests/fixtures/otel/ag016_otlp_benign.jsonl")  # two export lines
    [a] = Engine([b]).evaluate(b, attack)
    assert a.context["tool_name"] == "payments.create_transfer" and a.context["hops"] == 1
    assert "nested sink span(s)" in a.evidence[0]  # the MCP client span under the agent's call
    assert Engine([b]).evaluate(b, benign) == []
    assert [len(attack), len(benign)] == [6, 6]


def test_otlp_mapping_and_why_context_edges_exist(root):
    doc = json.loads((root / "tests/fixtures/otel/ag016_otlp_attack.json").read_text(encoding="utf-8"))
    evs = {e["span_id"][-1]: e for e in from_otlp([doc])}
    assert evs["1"]["input_origin"] == "user" and evs["1"]["parent_span_id"] is None
    assert evs["3"]["input_origin"] == "tool_output" and evs["3"]["source_trust"] == "untrusted"
    assert json.loads(evs["3"]["tool_args"]) == {"url": "https://supplier-portal.example/invoice/7781"}
    assert evs["6"]["server_id"] == "mcp-finance.internal:443" and evs["6"]["mcp_method"] == "tools/call"
    assert evs["4"]["input_span_ids"] == [evs["3"]["span_id"]]     # inferred: tool result -> next turn
    assert "input_span_ids" not in evs["2"]                        # started before the tool ran
    bare = from_otlp([doc], infer_context_edges=False)
    assert find(bare, untrusted, privileged, 3) == []              # siblings only: parent edges miss it


def test_otlp_links_and_extension_attributes():
    def s(sid, **kw):
        return {"traceId": "AB" * 16, "spanId": sid, "startTimeUnixNano": "1", "endTimeUnixNano": "2", **kw}
    doc = {"resourceSpans": [{"scopeSpans": [{"spans": [
        s("01", attributes=[{"key": "gen_ai.operation.name", "value": {"stringValue": "retrieval"}},
                            {"key": "abm.input_origin", "value": {"stringValue": "memory"}}]),
        s("02", links=[{"traceId": "AB" * 16, "spanId": "01"}, {"traceId": "CD" * 16, "spanId": "09"}]),
    ]}]}]}
    a, b = from_otlp([doc], infer_context_edges=False)
    assert a["trace_id"] == "ab" * 16 and a["input_origin"] == "memory"  # abm.* beats inference
    assert b["input_span_ids"] == ["01"]                                  # other-trace link dropped


def test_load_events_mixes_normalized_and_otlp_lines(tmp_path, root):
    otlp = (root / "tests/fixtures/otel/ag016_otlp_benign.jsonl").read_text(encoding="utf-8")
    f = tmp_path / "mixed.jsonl"
    f.write_text('{"timestamp": "2026-10-01T13:00:00Z", "prompt": "hi"}\n' + otlp, encoding="utf-8")
    evs = load_events(f)
    assert evs[0] == {"timestamp": "2026-10-01T13:00:00Z", "prompt": "hi"} and len(evs) == 7


# ---------------------------------------------------------------- compilers
@pytest.mark.parametrize("bid", PROVENANCE_IDS)
def test_kql_unrolls_joins_to_max_hops(behaviors, bid):
    b = behaviors[bid]
    q = TARGETS["kql"][0](b)
    n = b.detection.provenance.max_hops
    assert "union isfuzzy=true AIAgentToolCalls, AIMCPGatewayEvents" in q
    assert "FromSpanId = ParentSpanId" in q and "mv-expand FromSpanId = InputSpanIds" in q
    assert f"let Hop{n} = Hop{n - 1}" in q and f"Hop{n + 1}" not in q
    assert f"union {', '.join(f'Hop{i}' for i in range(1, n + 1))}" in q
    assert not is_stub(q)


def test_kql_drops_self_referencing_edges(behaviors):
    """Regression (found by differential fuzzing): a span listing itself in InputSpanIds made the
    compiled rule reach it in one hop while the engine ignores self-references."""
    q = TARGETS["kql"][0](behaviors["BHV-AG-016"])
    edges = q[q.index("let Edges"):q.index("let Sources")]
    assert "| where FromSpanId != ToSpanId" in edges
    assert edges.index("FromSpanId != ToSpanId") < edges.index("summarize Edge")
    assert find([sp("a", inputs=["a"], source_trust="untrusted", tool_class="privileged")],
                untrusted, privileged, 3) == []


def test_kql_source_and_sink_conditions(behaviors):
    q = TARGETS["kql"][0](behaviors["BHV-EXF-014"])
    sources = q[q.index("let Sources"):q.index("let Hop1")]
    sink = q[q.index("| join kind=inner (Spans"):]
    assert 'ToolClass == "secret_read"' in sources
    assert 'ToolClass == "egress"' in sink and "DestinationAllowlisted == false" in sink


@pytest.mark.parametrize("target", ["spl", "sigma"])
@pytest.mark.parametrize("bid", PROVENANCE_IDS)
def test_spl_and_sigma_emit_stub_and_warn(behaviors, caplog, target, bid):
    with caplog.at_level(logging.WARNING, logger="abm.compilers"):
        out = TARGETS[target][0](behaviors[bid])
    assert is_stub(out) and f"NOT EXPRESSIBLE IN {target.upper()}" in out
    assert [r.levelname for r in caplog.records] == ["WARNING"] and bid in caplog.text
    if target == "sigma":
        assert [d for d in yaml.safe_load_all(out) if d is not None] == []  # no rule documents
    else:
        assert all(line.startswith("```") and line.endswith("```") for line in out.splitlines())


def test_spl_header_comments_are_closed(behaviors):
    """SPL comments are ```delimited```: an unclosed header line turns the next line into search terms."""
    for b in behaviors.values():
        for line in TARGETS["spl"][0](b).splitlines():
            if line.startswith("```"):
                assert line.count("```") == 2 and line.endswith("```"), (b.id, line)


def test_cli_compile_reports_stubs(root, tmp_path, capsys):
    assert main(["--root", str(root), "compile", "--target", "spl", "--out", str(tmp_path)]) == 0
    cap = capsys.readouterr()
    assert "2 not-expressible stub(s)" in cap.out
    assert cap.err.count("[WARNING] BHV-") == 2 and "BHV-AG-016: not expressible in spl" in cap.err
