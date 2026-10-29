"""Countermeasure resolver: turns alerts into gated, templated response plans and executes them."""

from __future__ import annotations

import json
import re
import urllib.request
from dataclasses import asdict, dataclass, field
from typing import Any, Protocol

from abm.models import Behavior


@dataclass(frozen=True)
class ActionSpec:
    requires_approval: bool
    reversible: bool
    blast_radius: str  # request | session | principal | model | source | pipeline | service | org
    description: str


ACTION_REGISTRY: dict[str, ActionSpec] = {
    "block_request":     ActionSpec(False, True,  "request",   "Reject the offending request"),
    "redact_output":     ActionSpec(False, True,  "request",   "Redact sensitive spans from model output"),
    "strip_content":     ActionSpec(False, True,  "request",   "Strip instruction-bearing spans from retrieved content"),
    "deny_tool_call":    ActionSpec(False, True,  "request",   "Deny an agent tool invocation"),
    "cap_tokens":        ActionSpec(False, True,  "request",   "Cap max input/output tokens"),
    "increment_risk":    ActionSpec(False, True,  "principal", "Raise the principal's risk score"),
    "rate_limit":        ActionSpec(False, True,  "principal", "Throttle the principal"),
    "enforce_quota":     ActionSpec(False, True,  "principal", "Enforce spend/compute quota"),
    "degrade_output":    ActionSpec(False, True,  "model",     "Reduce output fidelity (e.g. top-1 label only)"),
    "open_incident":     ActionSpec(False, True,  "org",       "Open an incident in the SOC queue"),
    "notify":            ActionSpec(False, True,  "org",       "Notify a channel or distribution list"),
    "kill_session":      ActionSpec(False, True,  "session",   "Terminate the agent/LLM session"),
    "quarantine_source": ActionSpec(True,  True,  "source",    "Quarantine a retrieval source document"),
    "revoke_token":      ActionSpec(True,  True,  "principal", "Revoke the principal's credentials/tokens"),
    "block_deploy":      ActionSpec(False, True,  "service",   "Block a model artifact from deployment"),
    "pull_model":        ActionSpec(True,  True,  "service",   "Remove a model from serving / roll back"),
    "halt_pipeline":     ActionSpec(True,  True,  "pipeline",  "Halt a training/data pipeline"),
}

_TEMPLATE_RE = re.compile(r"\{\{\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*\}\}")


@dataclass
class Alert:
    behavior_id: str
    name: str
    severity: str
    technique: str
    tactics: list[str]
    context: dict[str, Any] = field(default_factory=dict)  # group keys / matched fields
    metrics: dict[str, float] = field(default_factory=dict)
    evidence: list[str] = field(default_factory=list)
    window_start: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class PlannedAction:
    action: str
    params: dict[str, Any]
    requires_approval: bool
    reversible: bool
    blast_radius: str
    status: str = "pending"  # pending | auto | awaiting_approval | executed | failed


def render(value: Any, ctx: dict[str, Any]) -> Any:
    if isinstance(value, str):
        return _TEMPLATE_RE.sub(lambda m: str(ctx.get(m.group(1), m.group(0))), value)
    if isinstance(value, dict):
        return {k: render(v, ctx) for k, v in value.items()}
    if isinstance(value, list):
        return [render(v, ctx) for v in value]
    return value


def plan(behavior: Behavior, alert: Alert) -> list[PlannedAction]:
    ctx = {**alert.context, **alert.metrics, "behavior_id": alert.behavior_id,
           "technique": alert.technique, "severity": alert.severity}
    actions: list[PlannedAction] = []
    for step in behavior.countermeasures.response:
        spec = ACTION_REGISTRY[step.action]
        gated = spec.requires_approval if step.requires_approval is None else step.requires_approval
        actions.append(
            PlannedAction(
                action=step.action,
                params=render(step.params, ctx),
                requires_approval=gated,
                reversible=spec.reversible,
                blast_radius=spec.blast_radius,
                status="awaiting_approval" if gated else "auto",
            )
        )
    return actions


class Executor(Protocol):
    def execute(self, alert: Alert, action: PlannedAction) -> PlannedAction: ...


class DryRunExecutor:
    """Default: records intent, changes nothing."""

    def execute(self, alert: Alert, action: PlannedAction) -> PlannedAction:
        if action.status == "auto":
            action.status = "executed(dry-run)"
        return action


class WebhookExecutor:
    """POSTs auto-approved actions to a SOAR webhook. Gated actions are never auto-executed."""

    def __init__(self, url: str, timeout: int = 10, headers: dict[str, str] | None = None):
        if not url.startswith("https://"):
            raise ValueError("webhook URL must be https")
        self.url, self.timeout, self.headers = url, timeout, headers or {}

    def execute(self, alert: Alert, action: PlannedAction) -> PlannedAction:
        if action.status != "auto":
            return action
        body = json.dumps({"alert": alert.to_dict(), "action": asdict(action)}).encode()
        req = urllib.request.Request(  # noqa: S310 (https enforced in __init__)
            self.url, data=body, method="POST",
            headers={"Content-Type": "application/json", **self.headers},
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:  # noqa: S310
                action.status = "executed" if 200 <= r.status < 300 else f"failed({r.status})"
        except OSError as e:
            action.status = f"failed({e.__class__.__name__})"
        return action
