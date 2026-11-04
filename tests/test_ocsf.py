"""OCSF adapter: extension integrity, per-source mapping, fixtures, round trip, findings and CLI."""

import copy
import importlib.util
import json
from datetime import datetime
from pathlib import Path

import pytest

from abm.cli import main
from abm.compilers.common import KQL_TABLES, SPL_SOURCES
from abm.engine import Engine, load_events
from abm.ocsf import (
    CLASSES,
    OCSF_VERSION,
    PLACEHOLDER_TAG,
    SOURCES,
    Flag,
    OcsfMappingError,
    alert_from_finding,
    detect_source,
    load_ocsf_events,
    normalize,
    read_ocsf,
    to_detection_finding,
    to_ocsf_event,
)
from abm.ocsf_schema import OcsfSchema
from abm.response import plan

ROOT = Path(__file__).resolve().parents[1]
OCSF_DIR = ROOT / "tests" / "fixtures" / "ocsf"
MANIFEST = json.loads((OCSF_DIR / "MANIFEST.json").read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def schema():
    return OcsfSchema.load(ROOT)


def _same_event(native: dict, got: dict, source: str) -> bool:
    """normalize() output equals the native event, except that nulls are dropped (OCSF omits
    them) and an alias is emitted next to its canonical field (identity.asn mirrors client_asn)."""
    exp = {k: v for k, v in native.items() if v is not None}
    aliases = SOURCES[source].aliases
    alias_keys = set(aliases) | set(aliases.values())
    return {k: v for k, v in got.items() if k in exp or k not in alias_keys} == exp


def _alerts(behaviors, events):
    out = []
    for a in Engine(behaviors).run(events):
        d = a.to_dict()
        d["context"] = {k: v for k, v in d["context"].items() if v is not None}
        out.append(d)
    return out


# ---------------------------------------------------------------- schema and extension
def test_sources_cover_every_siem_table():
    assert set(SOURCES) == set(KQL_TABLES) == set(SPL_SOURCES)


def test_base_schema_is_the_pinned_ocsf_release(schema):
    assert schema.version == OCSF_VERSION == "1.8.0"
    assert "ai_operation" in schema.profiles
    assert {"ai_model", "message_context"} <= set(schema.objects)
    for name, (cname, _, _) in CLASSES.items():
        assert schema.classes[cname].uid == name


def test_extension_is_internally_consistent(schema):
    assert schema.check_extension() == []
    assert schema.extension["name"] == "abm"


def test_extension_extends_the_core_ai_objects_instead_of_redefining_them(schema):
    assert ("object", "ai_model") in schema.patches
    assert ("object", "message_context") in schema.patches
    # model id, session id and token counts already exist in OCSF 1.8.0; the extension must not
    # redefine them.
    for core in ("ai_model", "message_context", "uid", "name", "ai_provider", "prompt_tokens",
                 "completion_tokens", "total_tokens", "ai_role_id"):
        assert core not in schema.ext_dictionary
    for core_obj in ("ai_model", "message_context", "technique", "mitigation"):
        assert core_obj not in schema.ext_objects


def test_every_declared_telemetry_field_has_an_ocsf_home(behaviors):
    missing = set()
    for b in behaviors.values():
        for ts in [*b.telemetry.required, *b.telemetry.optional]:
            spec = SOURCES[ts.source]
            for f in ts.fields:
                if f != "timestamp" and f not in spec.fields and f not in spec.aliases:
                    missing.add((ts.source, f))
    assert not missing


@pytest.mark.parametrize("source", sorted(SOURCES))
def test_mapping_paths_resolve_in_ocsf_plus_extension(schema, source):
    spec = SOURCES[source]
    for cuid in spec.classes():
        cname = CLASSES[cuid][0]
        paths = {}
        for fld, fs in spec.fields_for(cuid).items():
            path = fs.path if isinstance(fs, Flag) else fs
            attr = schema.resolve(cname, path)  # raises KeyError on an invalid path
            if isinstance(fs, Flag):
                assert attr.enum and str(fs.true) in attr.enum and str(fs.false) in attr.enum
            assert path not in paths, f"{source}: {fld} and {paths.get(path)} share {path}"
            paths[path] = fld


# ---------------------------------------------------------------- committed OCSF fixtures
def test_one_ocsf_fixture_per_source():
    assert {m["source"] for m in MANIFEST.values()} == set(SOURCES)
    assert sorted(p.name for p in OCSF_DIR.glob("*.ocsf.jsonl")) == sorted(MANIFEST)


def test_ocsf_fixtures_are_current():
    spec = importlib.util.spec_from_file_location("gen_ocsf", ROOT / "scripts" / "gen_ocsf_fixtures.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    for name, body in mod.render().items():
        assert (OCSF_DIR / name).read_text(encoding="utf-8").replace("\r\n", "\n") == body, name


@pytest.mark.parametrize("name", sorted(MANIFEST))
def test_ocsf_fixture_is_valid_ocsf(schema, name):
    m = MANIFEST[name]
    raw = read_ocsf(OCSF_DIR / name)
    assert len(raw) == m["events"]
    for ev in raw:
        assert schema.validate_event(ev) == []
        assert ev["class_uid"] == m["class_uid"]
        assert ev["metadata"]["log_name"] == m["source"]
        assert ev["metadata"]["version"] == OCSF_VERSION


@pytest.mark.parametrize("name", sorted(MANIFEST))
def test_ocsf_fixture_normalizes_to_the_native_fixture(name):
    m = MANIFEST[name]
    native = load_events(ROOT / m["native_fixture"])
    got = load_ocsf_events(OCSF_DIR / name)
    assert len(got) == len(native)
    for n, g in zip(native, got, strict=True):
        assert _same_event(n, g, m["source"]), (n, g)


@pytest.mark.parametrize("name", sorted(MANIFEST))
def test_ocsf_fixture_raises_the_same_alert_as_the_native_fixture(behaviors, name):
    m = MANIFEST[name]
    native_alerts = _alerts(behaviors.values(), load_events(ROOT / m["native_fixture"]))
    ocsf_alerts = _alerts(behaviors.values(), load_ocsf_events(OCSF_DIR / name))
    assert ocsf_alerts == native_alerts
    assert m["behavior"] in {a["behavior_id"] for a in ocsf_alerts}


@pytest.mark.parametrize("name", sorted(MANIFEST))
def test_source_is_detected_without_log_name(name):
    for ev in read_ocsf(OCSF_DIR / name):
        ev = copy.deepcopy(ev)
        del ev["metadata"]["log_name"]
        assert detect_source(ev) == MANIFEST[name]["source"]


# ---------------------------------------------------------------- full-corpus round trip
def test_every_behavior_fixture_round_trips_through_ocsf(behaviors, root):
    """native -> OCSF -> normalized: every behavior's declared tests still pass and every alert
    is identical, for all 143 behaviors and both fixtures each."""
    failures = []
    for b in behaviors.values():
        for tc in b.tests:
            native = load_events(root / tc.fixture)
            back = [normalize(to_ocsf_event(e, b.log_source)) for e in native]
            a_native = _alerts([b], native)
            a_ocsf = _alerts([b], back)
            if a_ocsf != a_native or (len(a_ocsf) > 0) != (tc.expect == "alert"):
                failures.append((b.id, tc.fixture))
    assert not failures


def test_time_only_ocsf_events_raise_the_same_alerts(behaviors):
    """Producers that send only `time` (epoch ms) and no time_dt still alert identically."""
    for name, m in MANIFEST.items():
        raw = read_ocsf(OCSF_DIR / name)
        for ev in raw:
            ev.pop("time_dt")
            ev["metadata"].pop("profiles", None)
        events = [normalize(e) for e in raw]
        want = _alerts(behaviors.values(), load_events(ROOT / m["native_fixture"]))
        got = _alerts(behaviors.values(), events)
        for a, b in zip(want, got, strict=True):
            ta, tb = (datetime.fromisoformat(x["window_start"].replace("Z", "+00:00"))
                      for x in (a, b))
            assert ta == tb
            assert {**a, "window_start": None, "context": {}} == {**b, "window_start": None, "context": {}}


# ---------------------------------------------------------------- mapping details
def test_placeholders_are_not_read_back():
    native = {"timestamp": "2026-10-01T14:00:00Z", "principal_id": "ci-bot",
              "event_type": "container_deploy", "image": "registry.example/llm:latest"}
    ev = to_ocsf_event(native, "cloud_audit")
    assert ev["api"]["operation"] == "container_deploy"  # required by API Activity
    tag = next(t for t in ev["metadata"]["tags"] if t["name"] == PLACEHOLDER_TAG)
    assert "api.operation" in tag["values"]
    assert normalize(ev) == native  # no invented 'operation' field


def test_unmapped_and_null_fields():
    native = {"timestamp": "2026-10-01T14:00:00Z", "model_id": "m", "has_emoji": True,
              "inter_arrival_s": None}
    ev = to_ocsf_event(native, "llm_gateway")
    assert ev["unmapped"] == {"has_emoji": True}
    assert "inter_arrival_s" not in ev["message_context"]
    assert normalize(ev) == {"timestamp": "2026-10-01T14:00:00Z", "model_id": "m", "has_emoji": True}


def test_boolean_stored_as_ocsf_enum():
    ev = to_ocsf_event({"timestamp": "2026-10-01T14:00:00Z", "principal_id": "u",
                        "actor_is_admin": False}, "agent_runtime")
    assert ev["actor"]["user"]["type_id"] == 1  # User
    assert normalize(ev)["actor_is_admin"] is False


def test_core_ai_objects_carry_model_session_and_tokens():
    ev = to_ocsf_event({"timestamp": "2026-10-01T14:00:00Z", "model_id": "gpt-x", "session_id": "s1",
                        "input_tokens": 10, "output_tokens": 5, "total_tokens": 15,
                        "prompt_hash": "h1"}, "llm_gateway")
    assert ev["ai_model"]["uid"] == "gpt-x"
    want = {"uid": "s1", "prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15,
            "ai_role_id": 1}
    assert want.items() <= ev["message_context"].items()
    assert ev["ai_prompt"] == {"prompt_hash": "h1"}
    assert "ai_operation" in ev["metadata"]["profiles"]


def test_source_override_and_unknown_class():
    ev = to_ocsf_event({"timestamp": "2026-10-01T14:00:00Z", "principal_id": "u"}, "ml_workspace")
    del ev["metadata"]["log_name"]
    assert normalize(ev, "ml_workspace")["principal_id"] == "u"
    with pytest.raises(OcsfMappingError):
        normalize({"class_uid": 1001, "time": 0, "metadata": {}})
    with pytest.raises(OcsfMappingError):
        normalize(ev, "identity")  # identity expects Authentication (3002), not API Activity


def test_json_array_input(tmp_path):
    raw = read_ocsf(OCSF_DIR / "llm_gateway.ocsf.jsonl")
    p = tmp_path / "events.json"
    p.write_text(json.dumps(raw), encoding="utf-8")
    assert load_ocsf_events(p) == load_ocsf_events(OCSF_DIR / "llm_gateway.ocsf.jsonl")


# ---------------------------------------------------------------- Detection Finding output
def _alert(behaviors, bid, fixture):
    b = behaviors[bid]
    return b, Engine([b]).evaluate(b, load_events(ROOT / fixture))[0]


def test_detection_finding_is_valid_and_carries_atlas_in_the_extension(schema, behaviors, catalog):
    b, a = _alert(behaviors, "BHV-EXF-003", "tests/fixtures/extraction_burst.jsonl")
    f = to_detection_finding(a, b, catalog)
    assert schema.validate_event(f) == []
    assert (f["class_uid"], f["type_uid"], f["severity_id"]) == (2004, 200401, 4)
    am = f["atlas_mapping"]
    assert am["technique"]["uid"] == "AML.T0024.002"
    assert am["version"] == catalog.version
    assert {(t["uid"], t["atlas_relationship"]) for t in am["techniques"]} == {
        (t.id, t.relationship) for t in b.atlas.techniques}
    assert [t["uid"] for t in am["tactics"]] == b.atlas.tactics
    assert [m["uid"] for m in am["mitigations"]] == b.countermeasures.mitigations
    # attacks[] keeps to ATT&CK by default: only the behavior's attack_bridge
    assert [x["technique"]["uid"] for x in f["attacks"]] == b.attack_bridge
    assert not any("AML." in json.dumps(x) for x in f["attacks"])
    assert f["finding_info"]["analytic"] == {
        "uid": "BHV-EXF-003", "name": b.name, "type_id": 3, "type": "Statistical",
        "state_id": 1, "state": "Active", "category": "inference_gateway"}


def test_atlas_in_attacks_is_opt_in(schema, behaviors, catalog):
    b, a = _alert(behaviors, "BHV-SC-001", "tests/fixtures/sc_unsigned_load.jsonl")
    f = to_detection_finding(a, b, catalog, atlas_in_attacks=True)
    assert schema.validate_event(f) == []
    sub = f["attacks"][0]
    assert sub["technique"]["uid"] == "AML.T0010" and sub["sub_technique"]["uid"] == "AML.T0010.003"
    assert sub["version"] == catalog.version


def test_finding_round_trips_to_the_alert(behaviors, catalog):
    for bid, fx in [("BHV-PI-001", "tests/fixtures/pi_direct_attack.jsonl"),
                    ("BHV-EXF-003", "tests/fixtures/extraction_burst.jsonl"),
                    ("BHV-LM-002", "tests/fixtures/pack/lm002_attack.jsonl")]:
        b, a = _alert(behaviors, bid, fx)
        f = to_detection_finding(a, b, catalog)
        assert alert_from_finding(f) == a.to_dict()
        assert to_detection_finding(a, b, catalog)["finding_info"]["uid"] == f["finding_info"]["uid"]


def test_finding_with_response_plan_and_minimal_inputs(schema, behaviors, catalog):
    b, a = _alert(behaviors, "BHV-EXF-003", "tests/fixtures/extraction_burst.jsonl")
    f = to_detection_finding(a, b, catalog, response=plan(b, a))
    assert schema.validate_event(f) == []
    rows = {r["action_name"]: r for r in f["response_plan"]}
    assert rows["revoke_token"]["plan_status"] == "awaiting_approval"
    assert rows["rate_limit"]["params"]["principal"] == "sp-unknown-77"
    bare = to_detection_finding(a)  # no behavior, no catalog
    assert schema.validate_event(bare) == []
    assert bare["atlas_mapping"]["techniques"] == [
        {"uid": "AML.T0024.002", "src_url": "https://atlas.mitre.org/techniques/AML.T0024.002",
         "atlas_relationship": "primary"}]


# ---------------------------------------------------------------- CLI
def _replay(capsys, *extra):
    rc = main(["--root", str(ROOT), "replay", *extra])
    out, err = capsys.readouterr()
    return rc, [json.loads(x) for x in out.splitlines() if x.strip()], err


@pytest.mark.parametrize("name", ["llm_gateway.ocsf.jsonl", "inference_gateway.http.ocsf.jsonl",
                                  "identity.ocsf.jsonl"])
def test_cli_ocsf_input_matches_native_input(capsys, name):
    """End to end through `abm replay` (every fixture is covered in-process above)."""
    m = MANIFEST[name]
    rc1, native, _ = _replay(capsys, "--fixture", str(ROOT / m["native_fixture"]))
    rc2, ocsf, err = _replay(capsys, "--fixture", str(OCSF_DIR / name), "--input-format", "ocsf",
                             "--validate-ocsf", "--expect", "alert")
    assert rc1 == rc2 == 0
    assert "expect=alert: PASS" in err
    strip = [{**a, "context": {k: v for k, v in a["context"].items() if v is not None}} for a in native]
    assert ocsf == strip


def test_cli_ocsf_output_is_valid(capsys, schema):
    rc, findings, err = _replay(capsys, "--fixture", str(OCSF_DIR / "llm_gateway.ocsf.jsonl"),
                                "--input-format", "ocsf", "--output-format", "ocsf",
                                "--validate-ocsf", "--respond")
    assert rc == 0 and findings and "(ocsf -> ocsf)" in err
    for f in findings:
        assert f["class_uid"] == 2004 and schema.validate_event(f) == []
        assert all(r["plan_status"] for r in f["response_plan"])


def test_cli_rejects_unmappable_and_invalid_ocsf(capsys, tmp_path):
    p = tmp_path / "bad.jsonl"
    p.write_text(json.dumps({"class_uid": 1001, "time": 0, "metadata": {"version": "1.8.0"}}) + "\n")
    rc, _, err = _replay(capsys, "--fixture", str(p), "--input-format", "ocsf")
    assert rc == 2 and "cannot map OCSF event" in err
    ev = read_ocsf(OCSF_DIR / "llm_gateway.ocsf.jsonl")[0]
    del ev["actor"]  # required by API Activity
    p.write_text(json.dumps(ev) + "\n")
    rc, _, err = _replay(capsys, "--fixture", str(p), "--input-format", "ocsf", "--validate-ocsf")
    assert rc == 2 and "missing required 'actor'" in err
    rc, _, _ = _replay(capsys, "--fixture", str(p), "--input-format", "ocsf")
    assert rc == 0  # without --validate-ocsf the mapping is lenient
