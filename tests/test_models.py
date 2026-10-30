import copy

import pytest
import yaml
from pydantic import ValidationError

from abm.cli import main
from abm.models import Behavior, Condition, Metric

MINIMAL = {
    "id": "BHV-PI-099",
    "name": "x",
    "status": "experimental",
    "severity": "low",
    "confidence": "low",
    "description": "x",
    "atlas": {"tactics": ["AML.TA0005"], "techniques": [{"id": "AML.T0051.000"}]},
    "telemetry": {"required": [{"source": "llm_gateway", "fields": ["prompt"]}]},
    "detection": {"logic": "signature", "signatures": [{"field": "prompt", "patterns": ["x"]}]},
}


def make(**overrides):
    d = copy.deepcopy(MINIMAL)
    d.update(overrides)
    return Behavior.model_validate(d)


def test_minimal_valid():
    assert make().primary_technique == "AML.T0051.000"


@pytest.mark.parametrize("bad_id", ["BHV-XX-001", "PI-001", "BHV-PI-1"])
def test_rejects_bad_behavior_id(bad_id):
    with pytest.raises(ValidationError):
        make(id=bad_id)


def test_rejects_bad_atlas_ids():
    with pytest.raises(ValidationError):
        make(atlas={"tactics": ["TA0005"], "techniques": [{"id": "AML.T0051"}]})
    with pytest.raises(ValidationError):
        make(atlas={"tactics": ["AML.TA0005"], "techniques": [{"id": "T1059"}]})


def test_requires_primary_technique():
    with pytest.raises(ValidationError, match="primary"):
        make(atlas={"tactics": ["AML.TA0005"],
                    "techniques": [{"id": "AML.T0051", "relationship": "precondition"}]})


def test_stable_requires_positive_and_negative_tests():
    with pytest.raises(ValidationError, match="stable"):
        make(status="stable", tests=[{"fixture": "a.jsonl", "expect": "alert"}])


def test_threshold_condition_must_reference_metric():
    with pytest.raises(ValidationError, match="undefined metric"):
        make(detection={"logic": "windowed_threshold", "window": "1h",
                        "metrics": {"n": "count"}, "conditions": ["m > 1"]})


@pytest.mark.parametrize("window", ["0s", "0m", "0h", "0d", "00h"])
def test_threshold_window_must_be_positive(window):
    with pytest.raises(ValidationError, match="window must be greater than zero"):
        make(detection={"logic": "windowed_threshold", "window": window,
                        "metrics": {"n": "count"}, "conditions": ["n > 1"]})


@pytest.mark.parametrize("window,seconds", [("1s", 1), ("15m", 900), ("1h", 3600), ("2d", 172800)])
def test_positive_threshold_windows_remain_valid(window, seconds):
    b = make(detection={"logic": "windowed_threshold", "window": window,
                        "metrics": {"n": "count"}, "conditions": ["n > 1"]})
    assert b.detection.window_seconds == seconds


@pytest.mark.parametrize("pattern", ["(", "[unterminated"])
def test_invalid_signature_is_a_validation_error(pattern):
    with pytest.raises(ValidationError, match="invalid signature regex"):
        make(detection={"logic": "signature",
                        "signatures": [{"field": "prompt", "patterns": [pattern]}]})


@pytest.mark.parametrize("detection,message", [
    ({"logic": "signature", "signatures": [{"field": "prompt", "patterns": ["("]}]},
     "invalid signature regex"),
    ({"logic": "windowed_threshold", "window": "0h",
      "metrics": {"n": "count"}, "conditions": ["n > 1"]},
     "window must be greater than zero"),
])
def test_cli_reports_invalid_detection_and_continues(detection, message, tmp_path, root, capsys):
    invalid = copy.deepcopy(MINIMAL)
    invalid["id"] = "BHV-PI-098"
    invalid["detection"] = detection
    (tmp_path / "a-invalid.yaml").write_text(yaml.safe_dump(invalid), encoding="utf-8")
    (tmp_path / "b-valid.yaml").write_text(yaml.safe_dump(MINIMAL), encoding="utf-8")

    assert main(["--root", str(root), "validate", str(tmp_path)]) == 1
    output = capsys.readouterr().out
    assert "a-invalid.yaml" in output
    assert message in output
    assert "1 behavior(s), 1 error(s)" in output


def test_unknown_field_rejected():
    with pytest.raises(ValidationError):
        make(unexpected=True)


def test_condition_and_metric_parsing():
    c = Condition.parse("request_count >= 10.5")
    assert (c.metric, c.op, c.value) == ("request_count", ">=", 10.5)
    assert Metric.parse("dcount(session_id)").field == "session_id"
    with pytest.raises(ValueError):
        Metric.parse("sum")
    with pytest.raises(ValueError):
        Condition.parse("a >> 3")
