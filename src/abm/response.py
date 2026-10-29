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
    "step_up_auth":      ActionSpec(False, True,  "principal", "Require re-authentication / MFA for the principal"),
    "quarantine_vector_records": ActionSpec(False, True, "source", "Exclude vector-store records from retrieval"),
    "quarantine_artifact": ActionSpec(False, True, "service",  "Mark a model/dataset artifact as quarantined"),
    "disable_tool":      ActionSpec(True,  True,  "service",   "Disable an agent tool / MCP server for all agents"),
    "rotate_credentials": ActionSpec(True, True,  "service",   "Rotate credentials exposed to or by an AI component"),
    "purge_agent_memory": ActionSpec(True, False, "principal", "Delete poisoned entries from agent long-term memory"),
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


XSOAR_SEVERITY = {"low": 1, "medium": 2, "high": 3, "critical": 4}


class XsoarExecutor:
    """Creates one Cortex XSOAR incident per alert carrying the full response plan.

    XSOAR owns execution: its playbook runs `auto` actions and routes `awaiting_approval` ones to an
    analyst task. Auth uses an XSOAR API key; for XSOAR 8 / Cortex cloud tenants also pass the API key
    ID, which switches to the `x-xdr-auth-id` header and the `/xsoar/public/v1` API path.
    """

    def __init__(self, url: str, api_key: str, api_key_id: str | None = None,
                 incident_type: str = "AI Security Alert", timeout: int = 15, path: str | None = None):
        if not url.startswith("https://"):
            raise ValueError("XSOAR URL must be https")
        if not api_key:
            raise ValueError("XSOAR API key is required")
        self.url = url.rstrip("/")
        self.api_key, self.api_key_id = api_key, api_key_id
        self.incident_type, self.timeout = incident_type, timeout
        self.path = path or ("/xsoar/public/v1/incident" if api_key_id else "/incident")

    def headers(self) -> dict[str, str]:
        h = {"Content-Type": "application/json", "Accept": "application/json",
             "Authorization": self.api_key}
        if self.api_key_id:
            h["x-xdr-auth-id"] = str(self.api_key_id)
        return h

    def incident(self, alert: Alert, actions: list[PlannedAction]) -> dict[str, Any]:
        """XSOAR create-incident payload. Labels always survive; CustomFields need the matching
        incident fields (see integrations/xsoar/README.md)."""
        plan_rows = [asdict(a) for a in actions]
        labels = [{"type": "behavior_id", "value": alert.behavior_id},
                  {"type": "atlas_technique", "value": alert.technique}]
        labels += [{"type": "atlas_tactic", "value": t} for t in alert.tactics]
        labels += [{"type": f"context.{k}", "value": str(v)} for k, v in alert.context.items()]
        labels += [{"type": "planned_action", "value": f"{a.action}:{a.status}"} for a in actions]
        details = [f"{alert.name}", f"ATLAS {alert.technique} ({', '.join(alert.tactics)})", "Evidence:"]
        details += [f"- {e}" for e in alert.evidence]
        payload: dict[str, Any] = {
            "name": f"[{alert.behavior_id}] {alert.name}",
            "type": self.incident_type,
            "severity": XSOAR_SEVERITY.get(alert.severity, 0),
            "details": "\n".join(details),
            "labels": labels,
            "rawJSON": json.dumps({"alert": alert.to_dict(), "response_plan": plan_rows}),
            "CustomFields": {
                "abmbehaviorid": alert.behavior_id,
                "abmatlastechnique": alert.technique,
                "abmatlastactics": ", ".join(alert.tactics),
                "abmresponseplan": json.dumps(plan_rows),
            },
            "createInvestigation": True,
        }
        if alert.window_start:
            payload["occurred"] = alert.window_start
        return payload

    def execute_plan(self, alert: Alert, actions: list[PlannedAction]) -> list[PlannedAction]:
        req = urllib.request.Request(  # noqa: S310 (https enforced in __init__)
            self.url + self.path, data=json.dumps(self.incident(alert, actions)).encode(),
            method="POST", headers=self.headers(),
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:  # noqa: S310
                ok = 200 <= r.status < 300
                ref = json.loads(r.read() or b"{}").get("id", "?") if ok else None
                outcome = f"xsoar:{ref}" if ok else f"failed({r.status})"
        except (OSError, ValueError) as e:
            outcome = f"failed({e.__class__.__name__})"
        for a in actions:
            if outcome.startswith("failed"):
                a.status = outcome
            else:
                a.status = f"{'awaiting_approval' if a.status == 'awaiting_approval' else 'delegated'}({outcome})"
        return actions

    def execute(self, alert: Alert, action: PlannedAction) -> PlannedAction:
        return self.execute_plan(alert, [action])[0]


def run_plan(executor: Executor, alert: Alert, actions: list[PlannedAction]) -> list[PlannedAction]:
    """Executors that hand the whole plan to another system (XSOAR) get it in one call."""
    batch = getattr(executor, "execute_plan", None)
    if batch:
        return batch(alert, actions)
    return [executor.execute(alert, a) for a in actions]
