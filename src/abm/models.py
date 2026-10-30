"""Behavior definition model. The YAML behavior file is the contract; everything else is generated."""

from __future__ import annotations

import re
from enum import Enum
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

BEHAVIOR_ID_RE = re.compile(r"^BHV-(PI|JB|LK|EXF|EV|PO|SC|BD|AG|DOS|CH)-\d{3}$")
ATLAS_TACTIC_RE = re.compile(r"^AML\.TA\d{4}$")
ATLAS_TECHNIQUE_RE = re.compile(r"^AML\.T\d{4}(\.\d{3})?$")
ATLAS_MITIGATION_RE = re.compile(r"^AML\.M\d{4}$")
ATTACK_TECHNIQUE_RE = re.compile(r"^T\d{4}(\.\d{3})?$")
WINDOW_RE = re.compile(r"^(\d+)([smhd])$")
CONDITION_RE = re.compile(r"^\s*([a-z_][a-z0-9_]*)\s*(>=|<=|==|!=|>|<)\s*(-?\d+(?:\.\d+)?)\s*$")
METRIC_RE = re.compile(r"^(count|dcount|sum|avg|variance|max|min)(?:\(([a-z_][a-z0-9_]*)\))?$")


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Status(str, Enum):
    experimental = "experimental"
    test = "test"
    stable = "stable"
    deprecated = "deprecated"


class Level(str, Enum):
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class TechniqueRef(_Strict):
    id: str
    relationship: Literal["primary", "secondary", "precondition"] = "primary"

    @field_validator("id")
    @classmethod
    def _id(cls, v: str) -> str:
        if not ATLAS_TECHNIQUE_RE.match(v):
            raise ValueError(f"invalid ATLAS technique id: {v}")
        return v


class AtlasMapping(_Strict):
    tactics: list[str] = Field(min_length=1)
    techniques: list[TechniqueRef] = Field(min_length=1)

    @field_validator("tactics")
    @classmethod
    def _tactics(cls, v: list[str]) -> list[str]:
        for t in v:
            if not ATLAS_TACTIC_RE.match(t):
                raise ValueError(f"invalid ATLAS tactic id: {t}")
        return v

    @model_validator(mode="after")
    def _has_primary(self) -> AtlasMapping:
        if not any(t.relationship == "primary" for t in self.techniques):
            raise ValueError("at least one technique must have relationship: primary")
        return self

    @property
    def primary(self) -> list[str]:
        return [t.id for t in self.techniques if t.relationship == "primary"]


class TelemetrySource(_Strict):
    source: str
    fields: list[str] = Field(min_length=1)


class Telemetry(_Strict):
    required: list[TelemetrySource] = Field(min_length=1)
    optional: list[TelemetrySource] = Field(default_factory=list)


class Condition(BaseModel):
    """Parsed form of 'metric_name <op> number'."""

    metric: str
    op: str
    value: float

    @classmethod
    def parse(cls, expr: str) -> Condition:
        m = CONDITION_RE.match(expr)
        if not m:
            raise ValueError(f"invalid condition '{expr}' (expected: name <op> number)")
        return cls(metric=m.group(1), op=m.group(2), value=float(m.group(3)))


class Metric(BaseModel):
    """Parsed form of 'agg(field)' e.g. dcount(session_id), count."""

    agg: str
    field: str | None = None

    @classmethod
    def parse(cls, expr: str) -> Metric:
        m = METRIC_RE.match(expr.strip())
        if not m:
            raise ValueError(f"invalid metric '{expr}' (expected agg or agg(field))")
        agg, fld = m.group(1), m.group(2)
        if agg != "count" and not fld:
            raise ValueError(f"metric '{expr}': {agg} requires a field")
        return cls(agg=agg, field=fld)


class Signature(_Strict):
    field: str
    patterns: list[str] = Field(min_length=1)

    @field_validator("patterns")
    @classmethod
    def _compile(cls, v: list[str]) -> list[str]:
        for p in v:
            try:
                re.compile(p)
            except re.error as e:
                raise ValueError(f"invalid signature regex {p!r}: {e}") from e
        return v


class Detection(_Strict):
    logic: Literal["signature", "windowed_threshold", "field_match"]
    # signature
    signatures: list[Signature] = Field(default_factory=list)
    # windowed_threshold
    window: str | None = None
    group_by: list[str] = Field(default_factory=list)
    metrics: dict[str, str] = Field(default_factory=dict)
    conditions: list[str] = Field(default_factory=list)
    # field_match
    match: dict[str, Any] = Field(default_factory=dict)
    # common
    filters: dict[str, Any] = Field(default_factory=dict)
    false_positives: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def _shape(self) -> Detection:
        if self.logic == "signature" and not self.signatures:
            raise ValueError("signature logic requires 'signatures'")
        if self.logic == "field_match" and not self.match:
            raise ValueError("field_match logic requires 'match'")
        if self.logic == "windowed_threshold":
            if not (self.window and WINDOW_RE.match(self.window)):
                raise ValueError("windowed_threshold requires 'window' like 1h, 15m")
            if self.window_seconds == 0:
                raise ValueError("window must be greater than zero")
            if not self.conditions:
                raise ValueError("windowed_threshold requires 'conditions'")
            for expr in self.metrics.values():
                Metric.parse(expr)
            for c in self.parsed_conditions:
                if c.metric not in self.metrics:
                    raise ValueError(f"condition references undefined metric '{c.metric}'")
        return self

    @property
    def parsed_conditions(self) -> list[Condition]:
        return [Condition.parse(c) for c in self.conditions]

    @property
    def parsed_metrics(self) -> dict[str, Metric]:
        return {k: Metric.parse(v) for k, v in self.metrics.items()}

    @property
    def window_seconds(self) -> int:
        m = WINDOW_RE.match(self.window or "")
        if not m:
            return 0
        n, unit = int(m.group(1)), m.group(2)
        return n * {"s": 1, "m": 60, "h": 3600, "d": 86400}[unit]


class ResponseStep(_Strict):
    action: str
    params: dict[str, Any] = Field(default_factory=dict)
    requires_approval: bool | None = None  # overrides action registry default


class Countermeasures(_Strict):
    mitigations: list[str] = Field(default_factory=list)
    response: list[ResponseStep] = Field(default_factory=list)

    @field_validator("mitigations")
    @classmethod
    def _mit(cls, v: list[str]) -> list[str]:
        for m in v:
            if not ATLAS_MITIGATION_RE.match(m):
                raise ValueError(f"invalid ATLAS mitigation id: {m}")
        return v


class TestCase(_Strict):
    fixture: str
    expect: Literal["alert", "no_alert"]


class Behavior(_Strict):
    id: str
    name: str
    status: Status
    severity: Level
    confidence: Level
    description: str
    atlas: AtlasMapping
    attack_bridge: list[str] = Field(default_factory=list)
    telemetry: Telemetry
    detection: Detection
    countermeasures: Countermeasures = Field(default_factory=Countermeasures)
    tests: list[TestCase] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)

    # populated by loader, not part of YAML
    source_path: Path | None = Field(default=None, exclude=True)

    @field_validator("id")
    @classmethod
    def _id(cls, v: str) -> str:
        if not BEHAVIOR_ID_RE.match(v):
            raise ValueError(f"invalid behavior id '{v}' (expected BHV-<PREFIX>-NNN)")
        return v

    @field_validator("attack_bridge")
    @classmethod
    def _attack(cls, v: list[str]) -> list[str]:
        for t in v:
            if not ATTACK_TECHNIQUE_RE.match(t):
                raise ValueError(f"invalid ATT&CK technique id: {t}")
        return v

    @model_validator(mode="after")
    def _stable_needs_tests(self) -> Behavior:
        if self.status == Status.stable:
            expects = {t.expect for t in self.tests}
            if expects != {"alert", "no_alert"}:
                raise ValueError(
                    "stable behaviors require at least one 'alert' and one 'no_alert' test"
                )
        return self

    @property
    def primary_technique(self) -> str:
        return self.atlas.primary[0]

    @property
    def log_source(self) -> str:
        return self.telemetry.required[0].source
