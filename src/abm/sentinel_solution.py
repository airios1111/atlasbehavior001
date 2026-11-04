"""Microsoft Sentinel Content Hub solution, generated from the behaviors.

`abm sentinel-build` writes an Azure-Sentinel solution folder (integrations/sentinel/ by default):

    Analytic Rules/BHV-*.yaml                 Scheduled rules (compilers/sentinel.py)
    DataCollection/<Table>_CL.json            ARM: custom table + data collection endpoint + DCR, per source
    Workbooks/ABM.json                        Alerts by BehaviorId / ATLAS tactic + Navigator-layer coverage
    Playbooks/ABM-ResponsePlan/azuredeploy.json  Logic App that executes the alert's response plan
    Data/Solution_ABM.json, SolutionMetadata.json  Input for Microsoft's solution packaging tool

Microsoft's tool (Azure-Sentinel/Tools/Create-Azure-Sentinel-Solution/V3) turns that folder into
Package/mainTemplate.json + createUiDefinition.json; CI runs it and arm-ttk. `abm sentinel-validate`
checks the generated content locally against the rule-template constraints listed in RULE_* below.
"""

from __future__ import annotations

import json
import re
import uuid
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from abm import __version__
from abm.catalog import AtlasCatalog
from abm.compilers import sentinel
from abm.compilers.common import kql_table, pascal
from abm.coverage import SCORE_LABEL, compute, navigator_layer
from abm.engine import load_events
from abm.models import Behavior, Status
from abm.response import ACTION_REGISTRY

SOLUTION_NAME = "ATLAS Behavior Map"
# Folder under Azure-Sentinel/Solutions/. createSolutionV3.ps1 resolves the solution folder from the
# data file's Name, so the two must be identical (as in Microsoft's own solutions).
SOLUTION_FOLDER = SOLUTION_NAME
SOLUTION_VERSION = "3.0.0"
AUTHOR = "Andres Rios"
SUPPORT_LINK = "https://github.com/airios1111/atlasbehavior001/issues"
LAST_UPDATED = "2026-11-04T00:00:00.000Z"  # playbook metadata; bump with content changes
PLAYBOOK_NAME = "ABM-ResponsePlan"
WORKBOOK_ID = "sentinel-ATLASBehaviorMap"

RULES_DIR = "Analytic Rules"
DCR_DIR = "DataCollection"
WORKBOOK_PATH = "Workbooks/ABM.json"
PLAYBOOK_PATH = f"Playbooks/{PLAYBOOK_NAME}/azuredeploy.json"
DATA_PATH = "Data/Solution_ABM.json"
METADATA_PATH = "SolutionMetadata.json"
GENERATED_DIRS = (RULES_DIR, DCR_DIR)  # files here that the build doesn't produce are stale

ARM_SCHEMA = "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#"
LOGIC_SCHEMA = ("https://schema.management.azure.com/providers/Microsoft.Logic/schemas/2016-06-01/"
                "workflowdefinition.json#")
API = {
    "tables": "2025-07-01",
    "dcr": "2023-03-11",
    "dce": "2023-03-11",
    "workflows": "2019-05-01",
    "connections": "2016-06-01",
}
_GUID_NS = uuid.UUID("5b0f3d0e-9d7c-4a59-8c1e-2f6a3d7b9e10")  # workbook parameter ids


# ------------------------------------------------------------------ tables and DCRs
_DCR_TYPES = {"string": "string", "long": "long", "real": "real", "boolean": "boolean",
              "dynamic": "dynamic", "datetime": "datetime"}
_TABLE_TYPES = {**_DCR_TYPES, "datetime": "dateTime"}  # the tables API spells it dateTime


def _hint(spec: Any) -> set[str]:
    """Type tags a match/filter spec implies for its field."""
    def tag(v: Any) -> str:
        if isinstance(v, bool):
            return "bool"
        if isinstance(v, int):
            return "int"
        if isinstance(v, float):
            return "float"
        return "dynamic" if isinstance(v, (list, dict)) else "str"

    if not isinstance(spec, dict):
        return {tag(spec)}
    out: set[str] = set()
    for op, arg in spec.items():
        if op in ("in", "not_in"):
            out |= {tag(a) for a in arg}
        elif op == "ne":
            out.add(tag(arg))
        elif op == "regex":
            out.add("str")
        elif op in ("gt", "gte", "lt", "lte"):
            out.add("num")
    return out


def _resolve(tags: set[str]) -> str:
    if "dynamic" in tags:
        return "dynamic"
    if "num" in tags:
        tags = (tags - {"num"}) or {"float"}
    if tags <= {"int"} and tags:
        return "long"
    if tags <= {"int", "float"} and tags:
        return "real"
    if tags == {"bool"}:
        return "boolean"
    if tags <= {"str"}:
        return "string"
    raise ValueError(f"conflicting types {sorted(tags)}")


def table_schemas(behaviors: list[Behavior], root: Path) -> dict[str, dict[str, str]]:
    """source -> {normalized field: KQL type}. Fields: every field any behavior declares for the source
    plus what the detections read. Types: fixture values, then what the detection logic implies."""
    fields: dict[str, set[str]] = defaultdict(set)
    tags: dict[tuple[str, str], set[str]] = defaultdict(set)
    for b in behaviors:
        for src in (*b.telemetry.required, *b.telemetry.optional):
            fields[src.source] |= set(src.fields)
        fields[b.log_source] |= sentinel.detection_fields(b)
        d = b.detection
        for s in d.signatures:
            tags[b.log_source, s.field].add("str")
        for m in d.parsed_metrics.values():
            if m.field and m.agg in ("sum", "avg", "variance", "max", "min"):
                tags[b.log_source, m.field].add("num")
        for f, spec in {**d.filters, **d.match}.items():
            tags[b.log_source, f] |= _hint(spec)
    for b in behaviors:
        flds = fields[b.log_source]
        for tc in b.tests:
            path = root / tc.fixture
            if not path.is_file():
                continue
            for e in load_events(path):
                for k, v in e.items():
                    if k in flds and v is not None:
                        tags[b.log_source, k] |= _hint(v)
    out: dict[str, dict[str, str]] = {}
    for source in sorted(fields):
        cols: dict[str, str] = {}
        for f in sorted(fields[source]):
            if f == "timestamp":
                cols[f] = "datetime"
                continue
            try:
                cols[f] = _resolve(tags[source, f])
            except ValueError as e:
                raise ValueError(f"{source}.{f}: {e} across behaviors/fixtures") from e
        out[source] = cols
    return out


def _slug(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", s.lower()).strip("-")


def dcr_template(source: str, cols: dict[str, str]) -> dict[str, Any]:
    """ARM template: custom table <X>_CL, a data collection endpoint, and the DCR that maps normalized
    events (snake_case, `timestamp`) onto the table's columns (PascalCase, TimeGenerated)."""
    table = kql_table(source, "sentinel")
    stream = f"Custom-{table.removesuffix('_CL')}Raw"
    dcr_name = f"abm-{_slug(source)}"
    table_cols = [{"name": "TimeGenerated", "type": "dateTime"}]
    table_cols += [{"name": pascal(f), "type": _TABLE_TYPES[t]} for f, t in cols.items() if f != "timestamp"]
    stream_cols = [{"name": f, "type": _DCR_TYPES[t]} for f, t in cols.items()]
    projection = ["TimeGenerated = todatetime(timestamp)"]
    projection += [f"{pascal(f)} = {f}" for f in cols if f != "timestamp"]
    dce_id = "[resourceId('Microsoft.Insights/dataCollectionEndpoints', parameters('dataCollectionEndpointName'))]"
    dcr_id = f"[resourceId('Microsoft.Insights/dataCollectionRules', '{dcr_name}')]"
    return {
        "$schema": ARM_SCHEMA,
        "contentVersion": "1.0.0.0",
        "metadata": {
            "description": f"ATLAS Behavior Map: {table} custom table and the data collection rule that "
                           f"ingests normalized '{source}' events through the Logs Ingestion API.",
        },
        "parameters": {
            "workspaceName": {"type": "string", "metadata": {
                "description": "Log Analytics workspace of Microsoft Sentinel (same resource group)."}},
            "dataCollectionEndpointName": {"type": "string", "defaultValue": "abm-ingestion", "metadata": {
                "description": "Data collection endpoint shared by all ABM sources; created if missing."}},
            "location": {"type": "string", "defaultValue": "[resourceGroup().location]", "metadata": {
                "description": "Region of the workspace."}},
        },
        "resources": [
            {
                "type": "Microsoft.OperationalInsights/workspaces/tables",
                "apiVersion": API["tables"],
                "name": f"[format('{{0}}/{{1}}', parameters('workspaceName'), '{table}')]",
                "properties": {"plan": "Analytics", "schema": {"name": table, "columns": table_cols}},
            },
            {
                "type": "Microsoft.Insights/dataCollectionEndpoints",
                "apiVersion": API["dce"],
                "name": "[parameters('dataCollectionEndpointName')]",
                "location": "[parameters('location')]",
                "properties": {"networkAcls": {"publicNetworkAccess": "Enabled"}},
            },
            {
                "type": "Microsoft.Insights/dataCollectionRules",
                "apiVersion": API["dcr"],
                "name": dcr_name,
                "location": "[parameters('location')]",
                "dependsOn": [
                    f"[resourceId('Microsoft.OperationalInsights/workspaces/tables', parameters('workspaceName'), '{table}')]",
                    dce_id,
                ],
                "properties": {
                    "dataCollectionEndpointId": dce_id,
                    "streamDeclarations": {stream: {"columns": stream_cols}},
                    "destinations": {"logAnalytics": [{
                        "workspaceResourceId": "[resourceId('Microsoft.OperationalInsights/workspaces', parameters('workspaceName'))]",
                        "name": "sentinelWorkspace",
                    }]},
                    "dataFlows": [{
                        "streams": [stream],
                        "destinations": ["sentinelWorkspace"],
                        "transformKql": "source | project " + ", ".join(projection),
                        "outputStream": f"Custom-{table}",
                    }],
                },
            },
        ],
        "outputs": {
            "logsIngestionEndpoint": {"type": "string", "value":
                f"[reference({dce_id[1:-1]}, '{API['dce']}').logsIngestion.endpoint]"},
            "dataCollectionRuleImmutableId": {"type": "string", "value":
                f"[reference({dcr_id[1:-1]}, '{API['dcr']}').immutableId]"},
            "streamName": {"type": "string", "value": stream},
        },
    }


# ------------------------------------------------------------------ workbook
_ALERTS_LET = """let AbmAlerts = SecurityAlert
| summarize arg_max(TimeGenerated, *) by SystemAlertId
| extend CustomDetails = todynamic(tostring(todynamic(ExtendedProperties)["Custom Details"]))
| extend B = CustomDetails.BehaviorId, T = CustomDetails.AtlasTactics, P = CustomDetails.AtlasTechnique
| extend BehaviorId = tostring(iff(gettype(B) == "array", B[0], B)),
         AtlasTactics = tostring(iff(gettype(T) == "array", T[0], T)),
         AtlasTechnique = tostring(iff(gettype(P) == "array", P[0], P))
| where isnotempty(BehaviorId);
"""


def _kql_str(s: str) -> str:
    return json.dumps(s)


def _query_item(name: str, title: str, query: str, visualization: str, timed: bool = True) -> dict[str, Any]:
    content: dict[str, Any] = {"version": "KqlItem/1.0", "query": query, "size": 0, "title": title}
    if timed:
        content["timeContext"] = {"durationMs": 604800000}
        content["timeContextFromParameter"] = "TimeRange"
    content.update({"queryType": 0, "resourceType": "microsoft.operationalinsights/workspaces",
                    "visualization": visualization})
    return {"type": 3, "content": content, "name": name}


def _text_item(name: str, markdown: str) -> dict[str, Any]:
    return {"type": 1, "content": {"json": markdown}, "name": name}


def coverage_rows(layer: dict[str, Any], catalog: AtlasCatalog) -> list[dict[str, Any]]:
    """Navigator-layer entries as (tactic, technique, score, behaviors) rows, in layer order."""
    short = {re.sub(r"[^a-z0-9]+", "-", t.name.lower()).strip("-"): t for t in catalog.tactics.values()}
    rows = []
    for e in layer.get("techniques", []):
        tac = short.get(e.get("tactic", ""))
        behaviors = next((m["value"] for m in e.get("metadata", []) if m.get("name") == "behaviors"), "")
        rows.append({
            "tactic_id": tac.id if tac else "", "tactic": tac.name if tac else e.get("tactic", ""),
            "technique_id": e["techniqueID"], "technique": catalog.name(e["techniqueID"]),
            "score": int(e.get("score", 0)), "behaviors": behaviors,
        })
    return rows


def workbook(layer: dict[str, Any], catalog: AtlasCatalog) -> dict[str, Any]:
    rows = coverage_rows(layer, catalog)
    tactic_table = ", ".join(f"{_kql_str(t.id)}, {_kql_str(t.name)}" for t in catalog.tactics.values())

    # Per-tactic summary, in matrix order, as a static markdown table (coverage is a build-time fact).
    lines = ["| Tactic | Techniques in layer | " + " | ".join(f"{s}: {SCORE_LABEL[s]}" for s in (3, 2, 1)) + " |",
             "|---|---|---|---|---|"]
    for tac in catalog.tactics.values():
        rs = [r for r in rows if r["tactic_id"] == tac.id]
        if rs:
            counts = [sum(1 for r in rs if r["score"] == s) for s in (3, 2, 1)]
            lines.append(f"| {tac.id} {tac.name} | {len(rs)} | " + " | ".join(map(str, counts)) + " |")
    by_score = {s: sum(1 for r in rows if r["score"] == s) for s in (3, 2, 1)}
    summary = (
        "## MITRE ATLAS coverage\n"
        f"Snapshot of the ATLAS Navigator layer built with this rule set ({layer.get('description', '')}). "
        f"{len(rows)} technique/tactic entries: " + ", ".join(f"{by_score[s]} at score {s}" for s in (3, 2, 1))
        + ". Techniques with score 0 have no behavior and are not in the layer; run `abm gaps` for them.\n\n"
        + "\n".join(lines)
    )
    data = ",\n".join(
        "    " + ", ".join([_kql_str(r["tactic_id"]), _kql_str(r["tactic"]), _kql_str(r["technique_id"]),
                            _kql_str(r["technique"]), str(r["score"]), _kql_str(r["behaviors"])])
        for r in rows
    )
    score_case = ", ".join(f"Score == {s}, {_kql_str(f'{s} {SCORE_LABEL[s]}')}" for s in (3, 2, 1))
    coverage_query = (
        "datatable(TacticId:string, Tactic:string, TechniqueId:string, Technique:string, Score:int, "
        f"Behaviors:string) [\n{data}\n]\n"
        f"| extend Coverage = case({score_case}, \"0 none\")\n"
        "| project TacticId, Tactic, TechniqueId, Technique, Coverage, Behaviors\n"
        "| sort by TacticId asc, TechniqueId asc"
    )
    param_id = str(uuid.uuid5(_GUID_NS, "TimeRange"))
    return {
        "version": "Notebook/1.0",
        "items": [
            _text_item("text - title",
                       "# ATLAS Behavior Map\n"
                       "Alerts from the ABM analytic rules by behavior and MITRE ATLAS tactic, and the ATLAS "
                       "coverage of the installed rule set. ATLAS IDs come from each alert's custom details "
                       "(BehaviorId, AtlasTechnique, AtlasTactics)."),
            {"type": 9, "content": {
                "version": "KqlParameterItem/1.0",
                "parameters": [{
                    "id": param_id, "version": "KqlParameterItem/1.0", "name": "TimeRange",
                    "label": "Time range", "type": 4, "isRequired": True,
                    "typeSettings": {"selectableValues": [{"durationMs": ms} for ms in
                                                          (86400000, 604800000, 2592000000, 7776000000)],
                                     "allowCustom": True},
                    "value": {"durationMs": 604800000},
                }],
                "style": "pills", "queryType": 0, "resourceType": "microsoft.operationalinsights/workspaces",
            }, "name": "parameters - time range"},
            _query_item("query - alerts by behavior", "Alerts by BehaviorId",
                        _ALERTS_LET + "AbmAlerts\n| summarize Alerts = count() by BehaviorId\n"
                                      "| sort by Alerts desc", "barchart"),
            _query_item("query - alerts by tactic", "Alerts by ATLAS tactic",
                        _ALERTS_LET + f"let Tactics = datatable(Tactic:string, TacticName:string) [{tactic_table}];\n"
                        "AbmAlerts\n| mv-expand Tactic = split(AtlasTactics, \",\") to typeof(string)\n"
                        "| join kind=leftouter Tactics on Tactic\n"
                        "| summarize Alerts = count() by AtlasTactic = strcat(Tactic, \" \", TacticName)\n"
                        "| sort by Alerts desc", "barchart"),
            _query_item("query - alerts over time", "ABM alerts over time by ATLAS tactic",
                        _ALERTS_LET + "AbmAlerts\n| mv-expand Tactic = split(AtlasTactics, \",\") to typeof(string)\n"
                        "| summarize Alerts = count() by Tactic, bin(TimeGenerated, {TimeRange:grain})",
                        "timechart"),
            _query_item("query - recent alerts", "Recent ABM alerts",
                        _ALERTS_LET + "AbmAlerts\n| project TimeGenerated, AlertName, AlertSeverity, BehaviorId, "
                        "AtlasTechnique, AtlasTactics, SystemAlertId\n| sort by TimeGenerated desc\n| take 200",
                        "table"),
            _text_item("text - coverage", summary),
            _query_item("query - coverage", "ATLAS coverage by technique (Navigator layer)", coverage_query,
                        "table", timed=False),
        ],
        "fromTemplateId": WORKBOOK_ID,
        "$schema": "https://github.com/Microsoft/Application-Insights-Workbooks/blob/master/schema/workbook.json",
    }


# ------------------------------------------------------------------ playbook
def _conn(name: str) -> str:
    return f"@parameters('$connections')['{name}']['connectionId']"


def _record(status_expr: str) -> dict[str, Any]:
    return {"type": "AppendToArrayVariable", "inputs": {"name": "Results", "value": {
        "action": "@items('For_each_action')?['action']",
        "status": status_expr,
        "approval": "@variables('Decision')",
    }}}


def _case(action: str) -> dict[str, Any]:
    run = f"Run_{action}"
    return {
        "case": action,
        "actions": {
            run: {
                "type": "Http",
                "inputs": {
                    "method": "POST",
                    "uri": "@parameters('ActionEndpointUrl')",
                    "headers": {"Content-Type": "application/json"},
                    "body": {
                        "action": action,
                        "params": "@items('For_each_action')?['params']",
                        "plan_row": "@items('For_each_action')",
                        "behavior_id": "@outputs('Behavior_id')",
                        "alert": "@triggerBody()",
                    },
                    "authentication": {"type": "ManagedServiceIdentity",
                                       "audience": "@parameters('ActionEndpointAudience')"},
                },
            },
            f"Record_{action}": {
                **_record(f"@{{if(equals(actions('{run}')?['status'], 'Succeeded'), 'executed', "
                          f"concat('failed(', string(coalesce(outputs('{run}')?['statusCode'], "
                          f"actions('{run}')?['status'])), ')'))}}"),
                "runAfter": {run: ["Succeeded", "Failed", "TimedOut"]},
            },
        },
    }


def _first(expr: str) -> str:
    """Custom details arrive as one-element arrays; tolerate a bare string too."""
    return f"if(startsWith(string({expr}), '[\"'), first({expr}), {expr})"


def workflow_definition() -> dict[str, Any]:
    item = "items('For_each_action')"
    cd = "body('Parse_custom_details')"
    approval_body = (
        "<p>ATLAS Behavior Map response action <b>@{" + item + "?['action']}</b> is waiting for approval.</p>"
        "<p>Alert: @{triggerBody()?['AlertDisplayName']}<br>Behavior: @{outputs('Behavior_id')}<br>"
        "Parameters: @{string(" + item + "?['params'])}<br>Blast radius: @{" + item + "?['blast_radius']}, "
        "reversible: @{" + item + "?['reversible']}</p>"
    )
    return {
        "$schema": LOGIC_SCHEMA,
        "contentVersion": "1.0.0.0",
        "parameters": {
            "$connections": {"type": "Object"},
            "ActionEndpointUrl": {"type": "String"},
            "ActionEndpointAudience": {"type": "String"},
            "ApproverEmail": {"type": "String"},
        },
        "triggers": {
            "Microsoft_Sentinel_alert": {
                "type": "ApiConnectionWebhook",
                "inputs": {
                    "body": {"callback_url": "@{listCallbackUrl()}"},
                    "host": {"connection": {"name": _conn("azuresentinel")}},
                    "path": "/subscribe",
                },
            },
        },
        "actions": {
            "Parse_custom_details": {
                "type": "ParseJson",
                "inputs": {
                    "content": "@json(coalesce(triggerBody()?['ExtendedProperties']?['Custom Details'], '{}'))",
                    "schema": {"type": "object"},
                },
            },
            "Behavior_id": {
                "type": "Compose",
                "inputs": "@{" + _first(cd + "?['BehaviorId']") + "}",
                "runAfter": {"Parse_custom_details": ["Succeeded"]},
            },
            "Response_plan": {
                "type": "Compose",
                "inputs": "@json(" + _first(cd + "?['ResponsePlan']") + ")",
                "runAfter": {"Behavior_id": ["Succeeded"]},
            },
            "Initialize_results": {
                "type": "InitializeVariable",
                "inputs": {"variables": [{"name": "Results", "type": "array", "value": "@createArray()"}]},
                "runAfter": {"Response_plan": ["Succeeded"]},
            },
            "Initialize_decision": {
                "type": "InitializeVariable",
                "inputs": {"variables": [{"name": "Decision", "type": "string", "value": "pending"}]},
                "runAfter": {"Initialize_results": ["Succeeded"]},
            },
            "For_each_action": {
                "type": "Foreach",
                "foreach": "@outputs('Response_plan')",
                "runtimeConfiguration": {"concurrency": {"repetitions": 1}},
                "runAfter": {"Initialize_decision": ["Succeeded"]},
                "actions": {
                    "Approval_gate": {
                        "type": "If",
                        "expression": {"and": [{"equals": [f"@{item}?['status']", "awaiting_approval"]}]},
                        "actions": {
                            "Send_approval_email": {
                                "type": "ApiConnectionWebhook",
                                "inputs": {
                                    "host": {"connection": {"name": _conn("office365")}},
                                    "path": "/approvalmail/$subscriptions",
                                    "body": {
                                        "NotificationUrl": "@{listCallbackUrl()}",
                                        "Message": {
                                            "To": "@parameters('ApproverEmail')",
                                            "Subject": f"ABM approval needed: @{{{item}?['action']}} for "
                                                       "@{outputs('Behavior_id')}",
                                            "Options": "Approve, Reject",
                                            "Body": approval_body,
                                            "Importance": "High",
                                            "HideHTMLMessage": False,
                                            "ShowHTMLConfirmationDialog": False,
                                        },
                                    },
                                },
                                "limit": {"timeout": "[parameters('ApprovalTimeout')]"},
                            },
                            "Set_decision_from_approver": {
                                "type": "SetVariable",
                                "inputs": {"name": "Decision", "value":
                                           "@{if(equals(actions('Send_approval_email')?['status'], 'Succeeded'), "
                                           "body('Send_approval_email')?['SelectedOption'], 'no_response')}"},
                                "runAfter": {"Send_approval_email": ["Succeeded", "Failed", "TimedOut"]},
                            },
                        },
                        "else": {"actions": {
                            "Set_decision_auto": {"type": "SetVariable",
                                                  "inputs": {"name": "Decision", "value": "auto"}},
                        }},
                    },
                    "Execute_if_allowed": {
                        "type": "If",
                        "expression": {"or": [{"equals": ["@variables('Decision')", "auto"]},
                                              {"equals": ["@variables('Decision')", "Approve"]}]},
                        "runAfter": {"Approval_gate": ["Succeeded"]},
                        "actions": {
                            "Route_action": {
                                "type": "Switch",
                                "expression": f"@{item}?['action']",
                                "cases": {f"Case_{a}": _case(a) for a in ACTION_REGISTRY},
                                "default": {"actions": {
                                    "Record_unknown_action": _record("failed(unknown action)"),
                                }},
                            },
                        },
                        "else": {"actions": {
                            "Record_not_approved": _record("@{concat('rejected(', variables('Decision'), ')')}"),
                        }},
                    },
                },
            },
            "Results_table": {
                "type": "Table",
                "inputs": {"from": "@variables('Results')", "format": "HTML"},
                "runAfter": {"For_each_action": ["Succeeded", "Failed", "TimedOut"]},
            },
            "Alert_-_Get_incident": {
                "type": "ApiConnection",
                "inputs": {
                    "host": {"connection": {"name": _conn("azuresentinel")}},
                    "method": "get",
                    "path": "/Incidents/subscriptions/@{encodeURIComponent(triggerBody()?['WorkspaceSubscriptionId'])}"
                            "/resourceGroups/@{encodeURIComponent(triggerBody()?['WorkspaceResourceGroup'])}"
                            "/workspaces/@{encodeURIComponent(triggerBody()?['WorkspaceId'])}"
                            "/alerts/@{encodeURIComponent(triggerBody()?['SystemAlertId'])}",
                },
                "runAfter": {"Results_table": ["Succeeded"]},
            },
            "Add_comment_to_incident_(V3)": {
                "type": "ApiConnection",
                "inputs": {
                    "host": {"connection": {"name": _conn("azuresentinel")}},
                    "method": "post",
                    "path": "/Incidents/Comment",
                    "body": {
                        "incidentArmId": "@body('Alert_-_Get_incident')?['id']",
                        "message": "<p><b>ATLAS Behavior Map response plan</b> for @{outputs('Behavior_id')}</p>"
                                   "@{body('Results_table')}",
                    },
                },
                "runAfter": {"Alert_-_Get_incident": ["Succeeded"]},
            },
        },
    }


def playbook() -> dict[str, Any]:
    managed = "[subscriptionResourceId('Microsoft.Web/locations/managedApis', parameters('location'), '{}')]"
    sentinel_conn = "[resourceId('Microsoft.Web/connections', variables('AzureSentinelConnectionName'))]"
    o365_conn = "[resourceId('Microsoft.Web/connections', variables('Office365ConnectionName'))]"
    return {
        "$schema": ARM_SCHEMA,
        "contentVersion": "1.0.0.0",
        "metadata": {
            "title": "ABM - Run ATLAS Behavior Map response plan",
            "description": "Runs the response plan that an ATLAS Behavior Map analytic rule attaches to its alert "
                           "(custom detail ResponsePlan). Steps with status auto run right away; steps with status "
                           "awaiting_approval are sent for Outlook approval first. Each ABM action name "
                           "(ACTION_REGISTRY) has its own Switch case that POSTs to your action endpoint; replace a "
                           "case with a native connector where you have one. Results are added to the incident "
                           "as a comment.",
            "prerequisites": [
                "An HTTPS action endpoint (Azure Function or API Management) that carries out ABM actions and "
                "accepts Microsoft Entra tokens for the audience you pass as ActionEndpointAudience.",
                "A mailbox or distribution list that approves gated actions (ApproverEmail).",
            ],
            "postDeployment": [
                "Authorize the Office 365 Outlook connection (API connections > office365-<PlaybookName>).",
                "Assign the playbook's managed identity the Microsoft Sentinel Responder role on the workspace.",
                "Allow the managed identity on the action endpoint.",
                "Create an automation rule that runs this playbook when an ABM alert is created.",
            ],
            "lastUpdateTime": LAST_UPDATED,
            "entities": ["Account", "IP", "Host"],
            "tags": ["MITRE ATLAS", "AI security", "Response"],
            "support": {"tier": "community"},
            "author": {"name": AUTHOR},
        },
        "parameters": {
            "PlaybookName": {"type": "string", "defaultValue": PLAYBOOK_NAME, "metadata": {
                "description": "Name of the Logic App."}},
            "ActionEndpointUrl": {"type": "string", "metadata": {
                "description": "HTTPS endpoint that carries out ABM actions. Receives {action, params, plan_row, "
                               "behavior_id, alert}."}},
            "ActionEndpointAudience": {"type": "string", "metadata": {
                "description": "Microsoft Entra audience (application ID URI) the action endpoint accepts."}},
            "ApproverEmail": {"type": "string", "metadata": {
                "description": "Who approves awaiting_approval steps."}},
            "ApprovalTimeout": {"type": "string", "defaultValue": "PT24H", "metadata": {
                "description": "ISO 8601 duration to wait for approval. No answer means the step is not run."}},
            "location": {"type": "string", "defaultValue": "[resourceGroup().location]", "metadata": {
                "description": "Region for the Logic App and its API connections."}},
        },
        "variables": {
            "AzureSentinelConnectionName": "[concat('azuresentinel-', parameters('PlaybookName'))]",
            "Office365ConnectionName": "[concat('office365-', parameters('PlaybookName'))]",
        },
        "resources": [
            {
                "type": "Microsoft.Web/connections",
                "apiVersion": API["connections"],
                "name": "[variables('AzureSentinelConnectionName')]",
                "location": "[parameters('location')]",
                "kind": "V1",
                "properties": {
                    "displayName": "[variables('AzureSentinelConnectionName')]",
                    "parameterValueType": "Alternative",
                    "api": {"id": managed.format("azuresentinel")},
                },
            },
            {
                "type": "Microsoft.Web/connections",
                "apiVersion": API["connections"],
                "name": "[variables('Office365ConnectionName')]",
                "location": "[parameters('location')]",
                "kind": "V1",
                "properties": {
                    "displayName": "[variables('Office365ConnectionName')]",
                    "api": {"id": managed.format("office365")},
                },
            },
            {
                "type": "Microsoft.Logic/workflows",
                "apiVersion": API["workflows"],
                "name": "[parameters('PlaybookName')]",
                "location": "[parameters('location')]",
                "identity": {"type": "SystemAssigned"},
                "tags": {"hidden-SentinelTemplateName": PLAYBOOK_NAME,
                         "hidden-SentinelTemplateVersion": "1.0"},
                "dependsOn": [sentinel_conn, o365_conn],
                "properties": {
                    "state": "Enabled",
                    "definition": workflow_definition(),
                    "parameters": {
                        "$connections": {"value": {
                            "azuresentinel": {
                                "connectionId": sentinel_conn,
                                "connectionName": "[variables('AzureSentinelConnectionName')]",
                                "id": managed.format("azuresentinel"),
                                "connectionProperties": {"authentication": {"type": "ManagedServiceIdentity"}},
                            },
                            "office365": {
                                "connectionId": o365_conn,
                                "connectionName": "[variables('Office365ConnectionName')]",
                                "id": managed.format("office365"),
                            },
                        }},
                        "ActionEndpointUrl": {"value": "[parameters('ActionEndpointUrl')]"},
                        "ActionEndpointAudience": {"value": "[parameters('ActionEndpointAudience')]"},
                        "ApproverEmail": {"value": "[parameters('ApproverEmail')]"},
                    },
                },
            },
        ],
    }


# ------------------------------------------------------------------ solution metadata
def solution_data(rule_files: list[str]) -> dict[str, Any]:
    return {
        "Name": SOLUTION_NAME,
        "Author": AUTHOR,
        "Logo": '<img src="https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Logos/Azure_Sentinel.svg" '
                'width="75px" height="75px">',
        "Description": "Detections for attacks on AI/ML systems (LLM gateways, inference endpoints, agents, "
                       "training pipelines, model registries), mapped to MITRE ATLAS. Generated by ATLAS Behavior "
                       f"Map {__version__} from one YAML definition per behavior.",
        "Workbooks": [WORKBOOK_PATH],
        "Analytic Rules": rule_files,
        "Playbooks": [PLAYBOOK_PATH],
        "BasePath": f"C:\\GitHub\\Azure-Sentinel\\Solutions\\{SOLUTION_FOLDER}",
        "Version": SOLUTION_VERSION,
        "Metadata": METADATA_PATH,
        "TemplateSpec": True,
        "Is1PConnector": False,
    }


def solution_metadata() -> dict[str, Any]:
    return {
        "publisherId": "azuresentinel",
        "offerId": "azure-sentinel-solution-atlasbehaviormap",
        "firstPublishDate": LAST_UPDATED[:10],
        "providers": [SOLUTION_NAME],
        "categories": {"domains": ["Security - Threat Protection", "Security - Others"]},
        "support": {"name": SOLUTION_NAME, "tier": "Community", "link": SUPPORT_LINK},
    }


# ------------------------------------------------------------------ build / check / write
def _json(data: Any) -> str:
    return json.dumps(data, indent=2) + "\n"


def shipped(behaviors: list[Behavior]) -> list[Behavior]:
    return sorted((b for b in behaviors if b.status != Status.deprecated), key=lambda b: b.id)


def build(behaviors: list[Behavior], catalog: AtlasCatalog, root: Path,
          layer: dict[str, Any] | None = None) -> dict[str, str]:
    """relative path -> file content (LF line endings) for the whole solution folder."""
    bs = shipped(behaviors)
    files: dict[str, str] = {}
    for b in bs:
        files[f"{RULES_DIR}/{b.id}.yaml"] = sentinel.compile_behavior(b)
    for source, cols in table_schemas(bs, root).items():
        files[f"{DCR_DIR}/{kql_table(source, 'sentinel')}.json"] = _json(dcr_template(source, cols))
    if layer is None:
        layer = navigator_layer(compute(behaviors, catalog, root), catalog)
    files[WORKBOOK_PATH] = _json(workbook(layer, catalog))
    files[PLAYBOOK_PATH] = _json(playbook())
    files[DATA_PATH] = _json(solution_data([f"{RULES_DIR}/{b.id}.yaml" for b in bs]))
    files[METADATA_PATH] = _json(solution_metadata())
    return dict(sorted(files.items()))


def _read(p: Path) -> str:
    return p.read_bytes().decode("utf-8").replace("\r\n", "\n")


def stale(files: dict[str, str], out: Path) -> list[str]:
    """Generated-folder files on disk that the build no longer produces."""
    found = []
    for d in GENERATED_DIRS:
        if (out / d).is_dir():
            found += [p.relative_to(out).as_posix() for p in sorted((out / d).iterdir()) if p.is_file()]
    return [f for f in found if f not in files]


def check(files: dict[str, str], out: Path) -> list[str]:
    """Differences between the build and the folder (line endings ignored)."""
    problems = []
    for rel, content in files.items():
        p = out / rel
        if not p.is_file():
            problems.append(f"missing: {rel}")
        elif _read(p) != content:
            problems.append(f"out of date: {rel}")
    problems += [f"stale: {rel}" for rel in stale(files, out)]
    return problems


def write(files: dict[str, str], out: Path) -> list[str]:
    """Write the build (LF on every OS) and remove stale generated files. Returns changed paths."""
    changed = []
    for rel in stale(files, out):
        (out / rel).unlink()
        changed.append(rel)
    for rel, content in files.items():
        p = out / rel
        if p.is_file() and _read(p) == content:
            continue
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8", newline="\n")
        changed.append(rel)
    return changed


# ------------------------------------------------------------------ validation
# Scheduled-rule template constraints (Microsoft.SecurityInsights alertRuleTemplates, Scheduled kind).
RULE_REQUIRED = ("id", "name", "description", "severity", "requiredDataConnectors", "queryFrequency",
                 "queryPeriod", "triggerOperator", "triggerThreshold", "tactics", "relevantTechniques",
                 "query", "version", "kind")
RULE_SEVERITIES = {"Informational", "Low", "Medium", "High"}
RULE_STATUSES = {"Available", "Installed", "NotAvailable"}
RULE_TACTICS = {"Reconnaissance", "ResourceDevelopment", "InitialAccess", "Execution", "Persistence",
                "PrivilegeEscalation", "DefenseEvasion", "CredentialAccess", "Discovery", "LateralMovement",
                "Collection", "Exfiltration", "CommandAndControl", "Impact", "PreAttack",
                "ImpairProcessControl", "InhibitResponseFunction"}
RULE_ENTITY_IDENTIFIERS = {
    "Account": {"Name", "FullName", "NTDomain", "DnsDomain", "UPNSuffix", "Sid", "AadTenantId", "AadUserId",
                "PUID", "IsDomainJoined", "DisplayName", "ObjectGuid"},
    "IP": {"Address"},
    "Host": {"DnsDomain", "NTDomain", "HostName", "FullName", "NetBiosName", "AzureID", "OMSAgentID",
             "OSFamily", "OSVersion", "IsDomainJoined"},
    "URL": {"Url"},
    "CloudApplication": {"AppId", "Name", "InstanceName"},
    "AzureResource": {"ResourceId"},
    "FileHash": {"Algorithm", "Value"},
}
# Custom-table column names Log Analytics reserves (TimeGenerated is required and added first).
RESERVED_COLUMNS = {"id", "type", "tenantid", "uniqueid", "title", "timegenerated"}
RULE_MAX_QUERY = 10000
RULE_MAX_ENTITY_MAPPINGS = 10
RULE_MAX_CUSTOM_DETAILS = 20
_PERIOD_RE = re.compile(r"^(\d+)([mhd])$")
_GUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
_TECH_RE = re.compile(r"^T\d{4}(\.\d{3})?$")
_DETAIL_KEY_RE = re.compile(r"^[A-Za-z][A-Za-z0-9]{0,19}$")


@dataclass
class Problem:
    path: str
    message: str

    def __str__(self) -> str:
        return f"[ERROR  ] {self.path}: {self.message}"


def _seconds(period: str) -> int | None:
    m = _PERIOD_RE.match(str(period))
    return int(m.group(1)) * {"m": 60, "h": 3600, "d": 86400}[m.group(2)] if m else None


def query_table(q: str) -> str:
    return next((ln.strip() for ln in q.splitlines() if ln.strip() and not ln.strip().startswith("//")), "")


_SPAN_UNION_RE = re.compile(r"^let \w+ = materialize\(union (?:isfuzzy=true )?(.+?)\s*$")


def query_tables(q: str) -> list[str]:
    """Tables a rule reads: the first query line, or the table list of a provenance rule, which
    starts with `let Spans = materialize(union isfuzzy=true A_CL, B_CL` (compilers/kql.py)."""
    first = query_table(q)
    m = _SPAN_UNION_RE.match(first)
    return [t.strip() for t in m.group(1).split(",")] if m else [first]


def check_rule(r: dict[str, Any], table_columns: dict[str, set[str]] | None = None) -> list[str]:
    """Problems with one Scheduled rule template. table_columns: table -> columns, for cross-checks."""
    errs = [f"missing field '{k}'" for k in RULE_REQUIRED if k not in r]
    if errs:
        return errs
    if not _GUID_RE.match(str(r["id"])):
        errs.append(f"id is not a lowercase GUID: {r['id']}")
    if r["kind"] != "Scheduled":
        errs.append(f"kind must be Scheduled, not {r['kind']}")
    if not str(r["name"]).strip():
        errs.append("empty name")
    if r["severity"] not in RULE_SEVERITIES:
        errs.append(f"severity {r['severity']} not in {sorted(RULE_SEVERITIES)}")
    if "status" in r and r["status"] not in RULE_STATUSES:
        errs.append(f"status {r['status']} not in {sorted(RULE_STATUSES)}")
    freq, period = _seconds(r["queryFrequency"]), _seconds(r["queryPeriod"])
    for key, v in (("queryFrequency", freq), ("queryPeriod", period)):
        if v is None:
            errs.append(f"{key} must look like 5m, 1h or 1d: {r[key]}")
        elif not 300 <= v <= 14 * 86400:
            errs.append(f"{key} {r[key]} outside 5m..14d")
    if freq and period and freq > period:
        errs.append("queryFrequency is longer than queryPeriod (events between runs are never queried)")
    if r["triggerOperator"] not in ("gt", "lt", "eq", "ne"):
        errs.append(f"triggerOperator {r['triggerOperator']} not in gt/lt/eq/ne")
    if not isinstance(r["triggerThreshold"], int) or r["triggerThreshold"] < 0:
        errs.append("triggerThreshold must be a non-negative integer")
    if not isinstance(r["requiredDataConnectors"], list):
        errs.append("requiredDataConnectors must be a list")
    tactics = r["tactics"] or []
    errs += [f"tactic {t} is not an ATT&CK tactic Sentinel accepts" for t in tactics if t not in RULE_TACTICS]
    for t in r["relevantTechniques"] or []:
        if not _TECH_RE.match(str(t)):
            errs.append(f"relevantTechniques entry {t} is not an ATT&CK technique ID")
            continue
        mapped = sentinel.attack_tactics(t)
        if mapped is None:
            errs.append(f"ATT&CK technique {t} has no tactic in compilers/sentinel.py ATTACK_TACTICS")
        elif not set(mapped) & set(tactics):
            errs.append(f"technique {t} belongs to {list(mapped)}, none listed in tactics")
    q = str(r["query"])
    if not 0 < len(q) <= RULE_MAX_QUERY:
        errs.append(f"query length {len(q)} outside 1..{RULE_MAX_QUERY}")
    cols: set[str] | None = None
    for table in query_tables(q):
        tcols = (table_columns or {}).get(table)
        if table_columns is not None and tcols is None:
            errs.append(f"query table {table} has no table definition in {DCR_DIR}/")
        elif tcols is not None:
            cols = (cols or set()) | set(tcols)

    def column_ok(c: str) -> bool:
        return bool(re.search(rf"\b{re.escape(c)}\b", q)) or (cols is not None and c in cols)

    ems = r.get("entityMappings") or []
    if len(ems) > RULE_MAX_ENTITY_MAPPINGS:
        errs.append(f"{len(ems)} entity mappings (max {RULE_MAX_ENTITY_MAPPINGS})")
    for em in ems:
        etype = em.get("entityType")
        if etype not in RULE_ENTITY_IDENTIFIERS:
            errs.append(f"entity type {etype} not supported here")
            continue
        fms = em.get("fieldMappings") or []
        if not 1 <= len(fms) <= 3:
            errs.append(f"{etype}: 1..3 field mappings required")
        for fm in fms:
            if fm.get("identifier") not in RULE_ENTITY_IDENTIFIERS[etype]:
                errs.append(f"{etype}: unknown identifier {fm.get('identifier')}")
            if not column_ok(str(fm.get("columnName"))):
                errs.append(f"{etype}: column {fm.get('columnName')} not produced by the query")
    details = r.get("customDetails") or {}
    if len(details) > RULE_MAX_CUSTOM_DETAILS:
        errs.append(f"{len(details)} custom details (max {RULE_MAX_CUSTOM_DETAILS})")
    for k, c in details.items():
        if not _DETAIL_KEY_RE.match(str(k)):
            errs.append(f"custom detail key {k} must be 1-20 letters/digits starting with a letter")
        if not column_ok(str(c)):
            errs.append(f"custom detail {k}: column {c} not produced by the query")
    agg = (r.get("eventGroupingSettings") or {}).get("aggregationKind", "SingleAlert")
    if agg not in ("SingleAlert", "AlertPerResult"):
        errs.append(f"aggregationKind {agg} not SingleAlert/AlertPerResult")
    if not re.match(r"^\d+\.\d+\.\d+$", str(r["version"])):
        errs.append(f"version {r['version']} is not a.b.c")
    return errs


def _walk(node: Any, path: str = "$"):
    yield path, node
    if isinstance(node, dict):
        for k, v in node.items():
            yield from _walk(v, f"{path}.{k}")
    elif isinstance(node, list):
        for i, v in enumerate(node):
            yield from _walk(v, f"{path}[{i}]")


def check_arm(t: dict[str, Any]) -> list[str]:
    """A few arm-ttk rules, for fast local feedback. CI runs the real arm-ttk."""
    errs = []
    if t.get("$schema") != ARM_SCHEMA or "contentVersion" not in t:
        errs.append("missing deploymentTemplate $schema / contentVersion")
    text = json.dumps(t)
    for name in t.get("parameters", {}):
        if f"parameters('{name}')" not in text:
            errs.append(f"parameter {name} is never used")
    for name in t.get("variables", {}):
        if f"variables('{name}')" not in text:
            errs.append(f"variable {name} is never used")
    loc = t.get("parameters", {}).get("location")
    if not loc or loc.get("defaultValue") != "[resourceGroup().location]":
        errs.append("needs a location parameter defaulting to [resourceGroup().location]")
    for res in t.get("resources", []):
        if "location" in res and res["location"] != "[parameters('location')]":
            errs.append(f"{res.get('type')}: location must be [parameters('location')]")
        if "preview" in str(res.get("apiVersion", "preview")):
            errs.append(f"{res.get('type')}: missing or preview apiVersion")
    for path, v in _walk(t):
        if v in ("", [], {}) and not path.endswith(".parameters") and path != "$.variables":
            errs.append(f"blank value at {path}")
        if isinstance(v, str):
            if v.startswith("[") and not v.startswith("[[") and not v.endswith("]"):
                errs.append(f"unterminated ARM expression at {path}")
            if re.search(r"https://management\.(azure|core\.windows)\.", v):
                errs.append(f"hardcoded management endpoint at {path}")
    return errs


def validate_dir(out: Path) -> list[Problem]:
    """Validate a solution folder as written on disk (what the packaging tool consumes)."""
    problems: list[Problem] = []
    table_columns: dict[str, set[str]] = {}
    for p in sorted((out / DCR_DIR).glob("*.json")) if (out / DCR_DIR).is_dir() else []:
        rel = p.relative_to(out).as_posix()
        try:
            t = json.loads(_read(p))
        except ValueError as e:
            problems.append(Problem(rel, f"invalid JSON: {e}"))
            continue
        problems += [Problem(rel, m) for m in check_arm(t)]
        for res in t.get("resources", []):
            if res.get("type") == "Microsoft.OperationalInsights/workspaces/tables":
                schema = res["properties"]["schema"]
                table_columns[schema["name"]] = {c["name"] for c in schema["columns"]}
                problems += [Problem(rel, f"column {c['name']} is a reserved Log Analytics column name")
                             for c in schema["columns"][1:]
                             if c["name"].lower() in RESERVED_COLUMNS or c["name"].startswith("_")]
    rules_dir = out / RULES_DIR
    rule_files = sorted(rules_dir.glob("*.yaml")) if rules_dir.is_dir() else []
    if not rule_files:
        problems.append(Problem(RULES_DIR, "no analytic rules"))
    ids: dict[str, str] = {}
    for p in rule_files:
        rel = p.relative_to(out).as_posix()
        try:
            r = yaml.safe_load(_read(p))
        except yaml.YAMLError as e:
            problems.append(Problem(rel, f"invalid YAML: {e}"))
            continue
        if not isinstance(r, dict):
            problems.append(Problem(rel, "not a mapping"))
            continue
        problems += [Problem(rel, m) for m in check_rule(r, table_columns)]
        if r.get("id") in ids:
            problems.append(Problem(rel, f"duplicate id {r['id']} (also {ids[r['id']]})"))
        ids[str(r.get("id"))] = rel
    pb = out / PLAYBOOK_PATH
    if pb.is_file():
        t = json.loads(_read(pb))
        problems += [Problem(PLAYBOOK_PATH, m) for m in check_arm(t)]
        wf = next((r for r in t["resources"] if r["type"] == "Microsoft.Logic/workflows"), None)
        cases = wf["properties"]["definition"]["actions"]["For_each_action"]["actions"]["Execute_if_allowed"][
            "actions"]["Route_action"]["cases"] if wf else {}
        routed = {c["case"] for c in cases.values()}
        if routed != set(ACTION_REGISTRY):
            problems.append(Problem(PLAYBOOK_PATH, f"Switch cases differ from ACTION_REGISTRY: "
                                                   f"missing {sorted(set(ACTION_REGISTRY) - routed)}, "
                                                   f"extra {sorted(routed - set(ACTION_REGISTRY))}"))
    else:
        problems.append(Problem(PLAYBOOK_PATH, "missing"))
    wb = out / WORKBOOK_PATH
    if wb.is_file():
        w = json.loads(_read(wb))
        if w.get("version") != "Notebook/1.0" or not w.get("items"):
            problems.append(Problem(WORKBOOK_PATH, "not a workbook (version Notebook/1.0 with items)"))
    else:
        problems.append(Problem(WORKBOOK_PATH, "missing"))
    data = out / DATA_PATH
    if data.is_file():
        d = json.loads(_read(data))
        listed = set(d.get("Analytic Rules", []))
        present = {p.relative_to(out).as_posix() for p in rule_files}
        if listed != present:
            problems.append(Problem(DATA_PATH, f"Analytic Rules list differs from {RULES_DIR}/: "
                                               f"unlisted {sorted(present - listed)[:5]}, "
                                               f"missing {sorted(listed - present)[:5]}"))
        for key in ("Workbooks", "Playbooks"):
            problems += [Problem(DATA_PATH, f"{key} entry {f} not found")
                         for f in d.get(key, []) if not (out / f).is_file()]
        if not (out / str(d.get("Metadata", ""))).is_file():
            problems.append(Problem(DATA_PATH, f"Metadata file {d.get('Metadata')} not found"))
    else:
        problems.append(Problem(DATA_PATH, "missing"))
    return problems
