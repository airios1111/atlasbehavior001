"""Microsoft Sentinel target and Content Hub solution: rules, tables/DCRs, workbook, playbook, packaging input."""

import json
import re
import uuid

import pytest
import yaml

from abm import sentinel_solution as sol
from abm.cli import main
from abm.compilers import TARGETS, kql, render, sentinel, sigma
from abm.compilers.common import kql_table, pascal, sentinel_period
from abm.coverage import compute, navigator_layer
from abm.engine import Engine, load_events
from abm.models import Status
from abm.response import _TEMPLATE_RE, ACTION_REGISTRY, plan

SOLUTION = "integrations/sentinel"


@pytest.fixture(scope="module")
def built(behaviors, catalog, root):
    return sol.build(list(behaviors.values()), catalog, root)


@pytest.fixture(scope="module")
def table_columns(built):
    cols = {}
    for rel, text in built.items():
        if rel.startswith(sol.DCR_DIR):
            schema = json.loads(text)["resources"][0]["properties"]["schema"]
            cols[schema["name"]] = {c["name"] for c in schema["columns"]}
    return cols


def _rule(b):
    return yaml.safe_load(sentinel.compile_behavior(b))


# ------------------------------------------------------------------ rule compiler
def test_every_behavior_compiles_to_a_valid_sentinel_rule(behaviors, table_columns):
    problems = {b.id: sentinel_problems for b in behaviors.values()
                if (sentinel_problems := sol.check_rule(_rule(b), table_columns))}
    assert problems == {}


def test_rule_id_is_uuid5_of_behavior_id_and_stable(behaviors):
    r = _rule(behaviors["BHV-EXF-003"])
    assert r["id"] == str(uuid.uuid5(sentinel._NS, "BHV-EXF-003")) == sentinel.rule_id("BHV-EXF-003")
    assert r["id"] == _rule(behaviors["BHV-EXF-003"])["id"]          # rebuild -> same GUID
    assert r["id"] != sigma.rule_id("BHV-EXF-003")                    # own namespace
    ids = [sentinel.rule_id(b) for b in behaviors]
    assert len(set(ids)) == len(ids)


@pytest.mark.parametrize(("seconds", "expected"), [
    (0, "1h"), (60, "5m"), (90, "5m"), (300, "5m"), (600, "10m"), (900, "15m"), (1800, "30m"),
    (3600, "1h"), (3601, "61m"), (86400, "1d"), (30 * 86400, "14d"),
])
def test_sentinel_period(seconds, expected):
    assert sentinel_period(seconds) == expected


def test_query_period_and_frequency_come_from_window(behaviors):
    exf = _rule(behaviors["BHV-EXF-003"])                               # window 1h
    assert exf["queryPeriod"] == exf["queryFrequency"] == "1h"
    dos = _rule(behaviors["BHV-DOS-002"])                               # window 1m, below Sentinel's 5m
    assert dos["queryPeriod"] == dos["queryFrequency"] == "5m"
    assert "ago(5m)" in dos["query"] and "bin(TimeGenerated, 1m)" in dos["query"]
    pi = _rule(behaviors["BHV-PI-001"])                                 # signature, no window
    assert pi["queryPeriod"] == pi["queryFrequency"] == sentinel_period(0)


def test_severity_and_status_mapping(behaviors):
    for b in behaviors.values():
        r = _rule(b)
        assert r["severity"] == {"low": "Low", "medium": "Medium", "high": "High", "critical": "High"}[b.severity.value]
        assert r["status"] == "Available"
        assert f"status {b.status.value}, severity {b.severity.value}" in r["description"]
    dep = behaviors["BHV-PI-001"].model_copy(update={"status": Status.deprecated})
    assert _rule(dep)["name"].startswith("[Deprecated] BHV-PI-001: ")


def test_attack_bridge_drives_sentinel_tactics_and_techniques(behaviors):
    r = _rule(behaviors["BHV-EXF-003"])
    assert r["tactics"] == ["Exfiltration"] and r["relevantTechniques"] == ["T1567"]
    assert sentinel.attack_tactics("T1550.001") == ("DefenseEvasion", "LateralMovement")  # via parent
    assert sentinel.attack_tactics("T9999") is None
    unmapped = {t for b in behaviors.values() for t in b.attack_bridge if sentinel.attack_tactics(t) is None}
    assert unmapped == set()
    no_bridge = _rule(behaviors["BHV-PI-001"])
    assert no_bridge["tactics"] == [] and no_bridge["relevantTechniques"] == []


def test_atlas_ids_travel_in_custom_details_and_description(behaviors):
    b = behaviors["BHV-EXF-003"]
    r = _rule(b)
    assert set(r["customDetails"]) == {"BehaviorId", "AtlasTechnique", "AtlasTechniques", "AtlasTactics",
                                       "ResponsePlan"}
    assert all(k == v for k, v in r["customDetails"].items())
    assert 'AtlasTechnique = "AML.T0024.002"' in r["query"]
    assert 'AtlasTechniques = "AML.T0024.002,AML.T0040"' in r["query"]
    assert 'AtlasTactics = strcat_array(AtlasTactics, ",")' in r["query"]
    assert "AML.TA0010" in r["description"] and "AML.T0024.002 (primary)" in r["description"]
    assert "AML.M0004" in r["description"]


def test_entity_mappings_from_group_by(behaviors):
    def ents(bid):
        return [(e["entityType"], e["fieldMappings"][0]["identifier"], e["fieldMappings"][0]["columnName"])
                for e in _rule(behaviors[bid]).get("entityMappings", [])]

    assert ents("BHV-EXF-003") == [("Account", "Name", "PrincipalId")]   # group_by principal_id, model_id
    assert ents("BHV-JB-003") == [("Account", "Name", "SessionId")]      # group_by session_id only
    assert ents("BHV-RC-001") == [("IP", "Address", "ClientIp")]         # group_by client_ip
    assert ents("BHV-C2-002") == [("Host", "HostName", "ClientHost")]
    assert ents("BHV-PI-001") == [("Account", "Name", "PrincipalId")]    # per-event: principal beats session
    assert ents("BHV-LM-002") == []                                      # token_id: nothing to map


def test_sentinel_profile_uses_custom_tables_and_default_is_unchanged(behaviors):
    b = behaviors["BHV-PI-001"]
    assert "\nAIGatewayLogs\n" in kql.compile_behavior(b)
    assert "\nAIGatewayLogs_CL\n" in kql.compile_behavior(b, profile="sentinel")
    assert render("kql", b) == TARGETS["kql"][0](b)
    assert render("sigma", b, "sentinel") == TARGETS["sigma"][0](b)      # profile only affects KQL
    assert kql_table("identity") == "SigninLogs" and kql_table("identity", "sentinel") == "AIIdentityEvents_CL"
    assert kql_table("new_source", "sentinel") == "NewSource_CL"
    for bb in behaviors.values():
        assert sol.query_table(_rule(bb)["query"]).endswith("_CL"), bb.id
    with pytest.raises(ValueError, match="unknown KQL profile"):
        kql_table("llm_gateway", "splunk")


def test_provenance_rules_read_every_span_table(behaviors, table_columns):
    """A provenance rule unions the span tables; each must be a generated _CL table and the rule's
    source/sink columns must exist there (regression: only the first query line was read)."""
    prov = [b for b in behaviors.values() if b.detection.logic == "provenance"]
    assert prov
    for b in prov:
        q = _rule(b)["query"]
        tables = sol.query_tables(q)
        expected = list(dict.fromkeys(kql_table(s.source, "sentinel") for s in b.telemetry.required))
        assert tables == expected and len(tables) > 1, b.id
        assert not sol.check_rule(_rule(b), table_columns), b.id
        cols = set().union(*(table_columns[t] for t in tables))
        assert {pascal(f) for f in sentinel.detection_fields(b)} <= cols, b.id
    assert sol.query_tables(_rule(behaviors["BHV-PI-001"])["query"]) == ["AIGatewayLogs_CL"]


# ------------------------------------------------------------------ response plan in the alert
def test_plan_param_values_bind_templates_to_columns():
    cols = {"principal_id": "PrincipalId", "session_id": "SessionId"}
    assert sentinel._value("{{principal_id}}", cols) == 'coalesce(tostring(PrincipalId), "{{principal_id}}")'
    assert sentinel._value("u:{{ principal_id }}/{{session_id}}!", cols) == (
        'strcat("u:", coalesce(tostring(PrincipalId), "{{ principal_id }}"), "/", '
        'coalesce(tostring(SessionId), "{{session_id}}"), "!")')
    assert sentinel._value("{{tool_name}}", cols) == '"{{tool_name}}"'   # not a column: stays text
    assert sentinel._value("ai-sec", cols) == '"ai-sec"'
    assert sentinel._value(25, cols) == "25" and sentinel._value(True, cols) == "true"


def test_response_plan_column_matches_abm_plan(behaviors, root):
    """Same actions, gating and statuses as abm.response.plan; and every template the reference engine
    fills from the alert context is bound to a result column in Sentinel."""
    for b in behaviors.values():
        q = _rule(b)["query"]
        rows = re.findall(r'bag_pack\("action", "([a-z_]+)".*"requires_approval", (true|false).*"status", "([a-z_]+)"\)',
                          q)
        positive = next((t for t in b.tests if t.expect == "alert"), None)
        if positive is None:
            continue
        alert = Engine([b]).evaluate(b, load_events(root / positive.fixture))[0]
        expected = plan(b, alert)
        assert rows == [(a.action, str(a.requires_approval).lower(), a.status) for a in expected], b.id
        ctx = {**alert.context, **alert.metrics}
        bound = sentinel.output_fields(b)
        for step in b.countermeasures.response:
            for v in step.params.values():
                for m in _TEMPLATE_RE.finditer(str(v)):
                    if m.group(1) in ctx:
                        assert m.group(1) in bound, (b.id, m.group(1))
                        assert f"tostring({pascal(m.group(1))})" in q, (b.id, m.group(1))


# ------------------------------------------------------------------ tables and DCRs
def test_tables_cover_every_column_the_queries_read(behaviors, table_columns):
    for b in behaviors.values():
        table = kql_table(b.log_source, "sentinel")
        missing = {pascal(f) for f in sentinel.detection_fields(b)} - table_columns[table]
        assert not missing, (b.id, table, missing)


def test_undeclared_detection_fields_still_get_columns(behaviors, root):
    """A filter on a field the telemetry block forgot to declare must still exist in the table,
    or Sentinel rejects the rule. Typed from the filter value."""
    b = behaviors["BHV-EXF-003"]
    d = b.detection.model_copy(update={"filters": {**b.detection.filters, "tenant_tier": {"gte": 2}}})
    probe = b.model_copy(update={"detection": d, "tests": []})
    cols = sol.table_schemas([probe], root)["inference_gateway"]
    assert cols["tenant_tier"] == "real" and "TenantTier" in sentinel.query(probe)


def test_dcr_maps_stream_onto_table(built):
    for rel, text in built.items():
        if not rel.startswith(sol.DCR_DIR):
            continue
        t = json.loads(text)
        table, _dce, dcr = t["resources"]
        cols = table["properties"]["schema"]["columns"]
        assert table["properties"]["schema"]["name"] == rel.split("/")[1].removesuffix(".json")
        assert cols[0] == {"name": "TimeGenerated", "type": "dateTime"}
        assert {c["type"] for c in cols} <= {"string", "long", "real", "boolean", "dynamic", "dateTime"}
        (stream, decl), = dcr["properties"]["streamDeclarations"].items()
        assert {c["type"] for c in decl["columns"]} <= {"string", "long", "real", "boolean", "dynamic", "datetime"}
        flow = dcr["properties"]["dataFlows"][0]
        assert flow["streams"] == [stream] and flow["outputStream"] == "Custom-" + table["properties"]["schema"]["name"]
        projected = re.findall(r"(\w+) = ", flow["transformKql"])
        assert projected == [c["name"] for c in cols]
        assert sol.check_arm(t) == []


def test_column_types_follow_fixtures_and_detection_logic(built):
    t = json.loads(built[f"{sol.DCR_DIR}/AIInferenceLogs_CL.json"])
    types = {c["name"]: c["type"] for c in t["resources"][0]["properties"]["schema"]["columns"]}
    assert types["InputEmbeddingNorm"] == "real"        # variance(input_embedding_norm)
    assert types["PrincipalId"] == "string"
    t = json.loads(built[f"{sol.DCR_DIR}/AIModelRegistryEvents_CL.json"])
    types = {c["name"]: c["type"] for c in t["resources"][0]["properties"]["schema"]["columns"]}
    assert types["DigestMatch"] == "boolean"            # fixtures carry true/false (and nulls)


def test_conflicting_field_types_fail_the_build():
    with pytest.raises(ValueError, match="conflicting types"):
        sol._resolve({"str", "int"})
    assert sol._resolve({"int", "float"}) == "real" and sol._resolve({"num"}) == "real"
    assert sol._resolve(set()) == "string" and sol._resolve({"int", "num"}) == "long"


# ------------------------------------------------------------------ workbook, playbook, data file
def test_workbook_alert_views_and_navigator_coverage(built, behaviors, catalog, root):
    w = json.loads(built[sol.WORKBOOK_PATH])
    assert w["version"] == "Notebook/1.0" and w["fromTemplateId"] == sol.WORKBOOK_ID
    queries = {i["name"]: i["content"].get("query", "") for i in w["items"] if i["type"] == 3}
    assert "by BehaviorId" in queries["query - alerts by behavior"]
    assert "split(AtlasTactics" in queries["query - alerts by tactic"]
    layer = navigator_layer(compute(list(behaviors.values()), catalog, root), catalog)
    cov = queries["query - coverage"]
    assert len(re.findall(r'"AML\.T\d{4}', cov)) == len(layer["techniques"])
    assert all(f'"{e["techniqueID"]}"' in cov for e in layer["techniques"])


def test_playbook_routes_every_registry_action_and_gates_approvals(built):
    t = json.loads(built[sol.PLAYBOOK_PATH])
    assert sol.check_arm(t) == []
    wf = next(r for r in t["resources"] if r["type"] == "Microsoft.Logic/workflows")
    d = wf["properties"]["definition"]
    assert "Microsoft_Sentinel_alert" in d["triggers"]
    loop = d["actions"]["For_each_action"]
    assert loop["runtimeConfiguration"]["concurrency"]["repetitions"] == 1
    gate = loop["actions"]["Approval_gate"]
    assert gate["expression"] == {"and": [{"equals": ["@items('For_each_action')?['status']", "awaiting_approval"]}]}
    assert gate["actions"]["Send_approval_email"]["inputs"]["path"] == "/approvalmail/$subscriptions"
    allowed = loop["actions"]["Execute_if_allowed"]
    assert allowed["runAfter"] == {"Approval_gate": ["Succeeded"]}
    cases = allowed["actions"]["Route_action"]["cases"]
    assert [c["case"] for c in cases.values()] == list(ACTION_REGISTRY)
    for c in cases.values():
        http = c["actions"][f"Run_{c['case']}"]
        assert http["inputs"]["body"]["action"] == c["case"]
        assert http["inputs"]["authentication"]["type"] == "ManagedServiceIdentity"
    assert "Add_comment_to_incident_(V3)" in d["actions"]


def test_solution_data_lists_shipped_rules(built, behaviors):
    d = json.loads(built[sol.DATA_PATH])
    shipped = sorted(b.id for b in behaviors.values() if b.status != Status.deprecated)
    assert d["Analytic Rules"] == [f"Analytic Rules/{i}.yaml" for i in shipped]
    assert d["Workbooks"] == [sol.WORKBOOK_PATH] and d["Playbooks"] == [sol.PLAYBOOK_PATH]
    assert d["Metadata"] == sol.METADATA_PATH and sol.METADATA_PATH in built


def test_committed_solution_is_current_and_valid(built, root):
    """integrations/sentinel is what Microsoft's packaging tool consumes; keep it in sync."""
    assert sol.check(built, root / SOLUTION) == [], "run `abm sentinel-build` and commit the result"
    assert [str(p) for p in sol.validate_dir(root / SOLUTION)] == []


# ------------------------------------------------------------------ validators catch real problems
def test_check_rule_rejects_invalid_rules(behaviors, table_columns):
    good = _rule(behaviors["BHV-EXF-003"])

    def errs(**change):
        return " | ".join(sol.check_rule({**good, **change}, table_columns))

    assert errs() == ""
    assert "severity Critical" in errs(severity="Critical")
    assert "outside 5m..14d" in errs(queryFrequency="1m")
    assert "longer than queryPeriod" in errs(queryFrequency="2h")
    assert "not an ATT&CK tactic" in errs(tactics=["Exfiltration", "ModelTheft"])
    assert "no tactic in compilers/sentinel.py" in errs(relevantTechniques=["T1078"])
    assert "none listed in tactics" in errs(tactics=["Impact"])
    assert "column Nope not produced" in errs(customDetails={"X": "Nope"})
    assert "custom detail key" in errs(customDetails={"Bad-Key": "BehaviorId"})
    assert "query length" in errs(query="x" * (sol.RULE_MAX_QUERY + 1))
    assert "has no table definition" in errs(query=good["query"].replace("AIInferenceLogs_CL", "Other_CL"))
    assert "not a lowercase GUID" in errs(id="BHV-EXF-003")
    assert "missing field 'kind'" in " ".join(sol.check_rule({k: v for k, v in good.items() if k != "kind"}))


def test_check_arm_rejects_common_arm_ttk_failures(built):
    t = json.loads(built[f"{sol.DCR_DIR}/AIGatewayLogs_CL.json"])
    t["parameters"]["unused"] = {"type": "string"}
    t["resources"][1]["location"] = "westeurope"
    t["resources"][1]["tags"] = {}
    msgs = " | ".join(sol.check_arm(t))
    assert "parameter unused is never used" in msgs
    assert "location must be [parameters('location')]" in msgs
    assert "blank value at $.resources[1].tags" in msgs


def test_check_and_write_detect_drift_stale_files_and_ignore_crlf(built, tmp_path):
    out = tmp_path / "sentinel"
    assert any(p.startswith("missing: ") for p in sol.check(built, out))
    sol.write(built, out)
    assert sol.check(built, out) == []
    rule = out / "Analytic Rules" / "BHV-PI-001.yaml"
    rule.write_bytes(rule.read_bytes().replace(b"\n", b"\r\n"))        # Windows checkout
    assert sol.check(built, out) == []
    rule.write_text(rule.read_text(encoding="utf-8").replace("triggerThreshold: 0", "triggerThreshold: 1"),
                    encoding="utf-8")
    (out / "Analytic Rules" / "BHV-XX-999.yaml").write_text("id: x\n", encoding="utf-8")
    assert sol.check(built, out) == ["out of date: Analytic Rules/BHV-PI-001.yaml",
                                     "stale: Analytic Rules/BHV-XX-999.yaml"]
    assert sorted(sol.write(built, out)) == ["Analytic Rules/BHV-PI-001.yaml", "Analytic Rules/BHV-XX-999.yaml"]
    assert sol.check(built, out) == [] and b"\r\n" not in rule.read_bytes()


# ------------------------------------------------------------------ CLI
def test_cli_compile_sentinel_target_and_profile(root, tmp_path, capsys):
    assert main(["--root", str(root), "compile", "--target", "sentinel", "--out", str(tmp_path / "s")]) == 0
    r = yaml.safe_load((tmp_path / "s" / "BHV-PI-001.yaml").read_text(encoding="utf-8"))
    assert r["kind"] == "Scheduled" and r["id"] == sentinel.rule_id("BHV-PI-001")
    assert main(["--root", str(root), "compile", "--target", "kql", "--profile", "sentinel",
                 "--out", str(tmp_path / "k")]) == 0
    assert "AIGatewayLogs_CL" in (tmp_path / "k" / "BHV-PI-001.kql").read_text(encoding="utf-8")


def test_cli_sentinel_build_check_and_validate(root, tmp_path, capsys):
    out = str(tmp_path / "sol")
    assert main(["--root", str(root), "sentinel-build", "--out", out, "--check"]) == 1
    assert "difference(s)" in capsys.readouterr().out
    assert main(["--root", str(root), "sentinel-build", "--out", out]) == 0
    assert main(["--root", str(root), "sentinel-build", "--out", out, "--check"]) == 0
    assert main(["--root", str(root), "sentinel-validate", out]) == 0
    assert "0 error(s)" in capsys.readouterr().out
    (tmp_path / "sol" / sol.WORKBOOK_PATH).unlink()
    assert main(["--root", str(root), "sentinel-validate", out]) == 1
    assert f"{sol.WORKBOOK_PATH}: missing" in capsys.readouterr().out
