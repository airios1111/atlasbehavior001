"""Compile behaviors to Microsoft Sentinel Scheduled analytic rules (Azure-Sentinel YAML template format).

The query is the KQL target compiled with the sentinel profile (_CL custom tables), plus the columns
Sentinel attaches to each alert as custom details:

- ATLAS IDs. Sentinel's tactics / relevantTechniques fields only accept ATT&CK, so those come from
  attack_bridge and the ATLAS mapping travels in custom details and the description.
- ResponsePlan: the same rows `abm.response.plan` produces (action, params, requires_approval,
  reversible, blast_radius, status), with {{field}} templates bound to the alert's columns. The ABM
  Logic App playbook reads it, like the XSOAR playbook reads `abmresponseplan`.
"""

from __future__ import annotations

import json
import uuid
from typing import Any

import yaml

from abm.compilers import kql
from abm.compilers.common import pascal, sentinel_period
from abm.models import Behavior, Status
from abm.response import _TEMPLATE_RE, Alert, plan

# Stable namespace: the rule GUID is uuid5(_NS, behavior id), so a rebuilt rule keeps its id and
# Content Hub updates the installed template instead of adding a duplicate.
_NS = uuid.UUID("65e6694c-0612-47cb-bffd-abd05df3fc8f")

RULE_VERSION = "1.0.0"

# Sentinel severities are Informational | Low | Medium | High. There is no Critical; the ABM severity
# is kept in the description and the Severity column.
SEVERITY = {"low": "Low", "medium": "Medium", "high": "High", "critical": "High"}

# Template status is Installed | Available | NotAvailable (service-managed), so the ABM lifecycle
# (experimental / test / stable) can't be carried there. Every shipped rule is Available; the ABM
# status is stated in the description, and deprecated rules get Microsoft's "[Deprecated]" prefix.
STATUS = {s.value: "Available" for s in Status}

# ATT&CK technique -> Sentinel tactic names, for the techniques used in attack_bridge. Sub-techniques
# resolve through their parent. `abm sentinel-validate` fails on an attack_bridge ID missing here.
ATTACK_TACTICS: dict[str, tuple[str, ...]] = {
    "T1003": ("CredentialAccess",),                  # OS Credential Dumping
    "T1005": ("Collection",),                        # Data from Local System
    "T1036": ("DefenseEvasion",),                    # Masquerading
    "T1071": ("CommandAndControl",),                 # Application Layer Protocol
    "T1102": ("CommandAndControl",),                 # Web Service
    "T1190": ("InitialAccess",),                     # Exploit Public-Facing Application
    "T1497": ("DefenseEvasion", "Discovery"),        # Virtualization/Sandbox Evasion
    "T1526": ("Discovery",),                         # Cloud Service Discovery
    "T1534": ("LateralMovement",),                   # Internal Spearphishing
    "T1550": ("DefenseEvasion", "LateralMovement"),  # Use Alternate Authentication Material
    "T1552": ("CredentialAccess",),                  # Unsecured Credentials
    "T1567": ("Exfiltration",),                      # Exfiltration Over Web Service
    "T1572": ("CommandAndControl",),                 # Protocol Tunneling
    "T1589": ("Reconnaissance",),                    # Gather Victim Identity Information
    "T1591": ("Reconnaissance",),                    # Gather Victim Org Information
    "T1595": ("Reconnaissance",),                    # Active Scanning
    "T1656": ("DefenseEvasion",),                    # Impersonation
}

# (entity type, identifier, candidate fields in preference order). One mapping per entity type, so a
# session id only becomes the Account when the rows carry no principal id.
ENTITY_FIELDS: tuple[tuple[str, str, tuple[str, ...]], ...] = (
    ("Account", "Name", ("principal_id", "session_id")),
    ("IP", "Address", ("client_ip", "ip")),
    ("Host", "HostName", ("client_host",)),
)

CUSTOM_DETAILS = ("BehaviorId", "AtlasTechnique", "AtlasTechniques", "AtlasTactics", "ResponsePlan")


def rule_id(behavior_id: str) -> str:
    return str(uuid.uuid5(_NS, behavior_id))


def attack_tactics(technique: str) -> tuple[str, ...] | None:
    """Sentinel tactics for an ATT&CK technique, or None if it isn't in ATTACK_TACTICS."""
    return ATTACK_TACTICS.get(technique) or ATTACK_TACTICS.get(technique.split(".")[0])


def schedule(b: Behavior) -> str:
    """queryPeriod == queryFrequency: each run evaluates one window, with no gaps and no overlap."""
    return sentinel_period(b.detection.window_seconds)


def detection_fields(b: Behavior) -> set[str]:
    """Normalized fields the behavior's query reads from its log-source table."""
    d = b.detection
    out = set(d.filters) | set(d.match) | set(d.group_by) | {s.field for s in d.signatures}
    out |= {m.field for m in d.parsed_metrics.values() if m.field}
    return out


def source_fields(b: Behavior) -> set[str]:
    """Fields present on rows of the behavior's table: its declared telemetry for that source plus
    whatever the detection reads."""
    declared = {f for src in (*b.telemetry.required, *b.telemetry.optional)
                if src.source == b.log_source for f in src.fields}
    return declared | detection_fields(b)


def output_fields(b: Behavior) -> set[str]:
    """Normalized fields that survive into the query's result rows (entity / template candidates)."""
    if b.detection.logic == "windowed_threshold":
        return set(b.detection.group_by) | set(b.detection.metrics)
    return source_fields(b) - {"timestamp"}


def entity_mappings(b: Behavior) -> list[dict[str, Any]]:
    avail = output_fields(b)
    out = []
    for etype, ident, candidates in ENTITY_FIELDS:
        f = next((c for c in candidates if c in avail), None)
        if f:
            out.append({"entityType": etype,
                        "fieldMappings": [{"identifier": ident, "columnName": pascal(f)}]})
    return out


def _lit(v: Any) -> str:
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (int, float)):
        return repr(v)
    if isinstance(v, (list, dict)):
        return f"dynamic({json.dumps(v)})"
    return json.dumps(str(v))


def _value(v: Any, columns: dict[str, str]) -> str:
    """A plan param as KQL. {{field}} templates bound to a result column become that column's value
    (falling back to the template text when empty, as abm.response.render does); others stay text."""
    if not isinstance(v, str):
        return _lit(v)
    parts: list[str] = []
    text, pos = "", 0
    for m in _TEMPLATE_RE.finditer(v):
        col = columns.get(m.group(1))
        text += v[pos:m.start()]
        pos = m.end()
        if col is None:
            text += m.group(0)
            continue
        if text:
            parts.append(_lit(text))
            text = ""
        parts.append(f"coalesce(tostring({col}), {_lit(m.group(0))})")
    text += v[pos:]
    if text or not parts:
        parts.append(_lit(text))
    return parts[0] if len(parts) == 1 else f"strcat({', '.join(parts)})"


def response_plan(b: Behavior) -> list[dict[str, Any]]:
    """Plan rows exactly as abm.response.plan builds them; alert-context templates stay unrendered."""
    alert = Alert(behavior_id=b.id, name=b.name, severity=b.severity.value,
                  technique=b.primary_technique, tactics=list(b.atlas.tactics))
    return [vars(a) for a in plan(b, alert)]


_PLAN_KEYS = ("action", "params", "requires_approval", "reversible", "blast_radius", "status")


def _plan_kql(b: Behavior) -> str:
    """`| extend ResponsePlan = ...`: one bag_pack per plan row, params bound to result columns."""
    columns = {f: pascal(f) for f in output_fields(b)}
    rows = []
    for r in response_plan(b):
        params = ", ".join(f"{_lit(k)}, {_value(v, columns)}" for k, v in r["params"].items())
        values = {k: _lit(r[k]) for k in _PLAN_KEYS if k != "params"}
        values["params"] = f"bag_pack({params})" if params else "dynamic({})"
        rows.append("    bag_pack(" + ", ".join(f"{_lit(k)}, {values[k]}" for k in _PLAN_KEYS) + ")")
    if not rows:
        return "| extend ResponsePlan = tostring(dynamic([]))"
    return "| extend ResponsePlan = tostring(pack_array(\n" + ",\n".join(rows) + "))"


def query(b: Behavior) -> str:
    techniques = ",".join(t.id for t in b.atlas.techniques)
    return (
        kql.compile_behavior(b, profile="sentinel")
        + f'| extend AtlasTactics = strcat_array(AtlasTactics, ","), AtlasTechniques = "{techniques}"\n'
        + _plan_kql(b) + "\n"
    )


def description(b: Behavior) -> str:
    techs = ", ".join(f"{t.id} ({t.relationship})" for t in b.atlas.techniques)
    lines = [
        " ".join(b.description.split()),
        "",
        f"MITRE ATLAS tactics: {', '.join(b.atlas.tactics)}. Techniques: {techs}."
        + (f" Mitigations: {', '.join(b.countermeasures.mitigations)}." if b.countermeasures.mitigations else ""),
        f"ABM behavior {b.id}: status {b.status.value}, severity {b.severity.value}, "
        f"confidence {b.confidence.value}.",
    ]
    if b.detection.false_positives:
        lines.append("False positives: " + "; ".join(b.detection.false_positives) + ".")
    lines.append("Generated by atlas-behavior-map. Do not edit; change the behavior YAML and rebuild.")
    return "\n".join(lines) + "\n"


def rule(b: Behavior) -> dict[str, Any]:
    period = schedule(b)
    tactics: list[str] = []
    for t in b.attack_bridge:
        for tac in attack_tactics(t) or ():
            if tac not in tactics:
                tactics.append(tac)
    out: dict[str, Any] = {
        "id": rule_id(b.id),
        "name": ("[Deprecated] " if b.status == Status.deprecated else "") + f"{b.id}: {b.name}",
        "description": description(b),
        "severity": SEVERITY[b.severity.value],
        "status": STATUS[b.status.value],
        "requiredDataConnectors": [],
        "queryFrequency": period,
        "queryPeriod": period,
        "triggerOperator": "gt",
        "triggerThreshold": 0,
        "tactics": tactics,
        "relevantTechniques": list(b.attack_bridge),
        "query": query(b),
        "entityMappings": entity_mappings(b),
        "customDetails": {k: k for k in CUSTOM_DETAILS},
        "eventGroupingSettings": {"aggregationKind": "AlertPerResult"},
        "version": RULE_VERSION,
        "kind": "Scheduled",
    }
    if not out["entityMappings"]:
        del out["entityMappings"]
    return out


class _Dumper(yaml.SafeDumper):
    pass


def _str(dumper: yaml.SafeDumper, s: str) -> yaml.ScalarNode:
    return dumper.represent_scalar("tag:yaml.org,2002:str", s, style="|" if "\n" in s else None)


_Dumper.add_representer(str, _str)


def dump(data: dict[str, Any]) -> str:
    return yaml.dump(data, Dumper=_Dumper, sort_keys=False, width=1000, allow_unicode=True)


def compile_behavior(b: Behavior) -> str:
    return dump(rule(b))
