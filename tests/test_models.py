import copy

import pytest
from pydantic import ValidationError

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
