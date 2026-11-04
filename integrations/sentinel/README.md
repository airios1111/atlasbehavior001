# Microsoft Sentinel integration (Content Hub solution)

`abm sentinel-build` turns the behaviors into a **Microsoft Sentinel solution** in the Azure-Sentinel repo layout.
One Scheduled analytic rule per behavior. Every alert carries its ATLAS mapping and its response plan, and a
Logic App playbook runs that plan:

```
normalized events ──► Logs Ingestion API ──► DCR ──► AI*_CL table ──► analytic rule BHV-* ──► alert
                                                                        ├─ tactics / relevantTechniques: ATT&CK (attack_bridge)
                                                                        ├─ entities: Account, IP, Host (from group_by)
                                                                        └─ custom details: BehaviorId, AtlasTechnique, AtlasTechniques,
                                                                           AtlasTactics, ResponsePlan
alert ──► automation rule ──► playbook ABM-ResponsePlan ──► auto: POST to your action endpoint
                                                          └─ awaiting_approval: Outlook approval first
```

Everything in this folder except this README and `ReleaseNotes.md` is generated. Don't edit it by hand.
Change the behavior YAML and run `abm sentinel-build` again. CI fails if the folder is out of date.

| Path | What it is |
|---|---|
| `Analytic Rules/BHV-*.yaml` | Scheduled rules (`compilers/sentinel.py`), one per non-deprecated behavior |
| `DataCollection/<Table>_CL.json` | ARM template per telemetry source: custom table, data collection endpoint and DCR |
| `Workbooks/ABM.json` | Alerts by BehaviorId and ATLAS tactic, plus ATLAS coverage from the Navigator layer |
| `Playbooks/ABM-ResponsePlan/azuredeploy.json` | Logic App that executes the response plan |
| `Data/Solution_ABM.json`, `SolutionMetadata.json` | Input for Microsoft's solution packaging tool |
| `Package/` (not committed) | `mainTemplate.json`, `createUiDefinition.json`, built by the packaging tool in CI |

How the rule fields are filled in:

| Rule field | Source |
|---|---|
| `id` | `uuid5(namespace, behavior id)`. The GUID doesn't change across rebuilds, so Content Hub updates the installed rule instead of adding a second copy |
| `queryPeriod`, `queryFrequency` | `detection.window`, both set to the same value so each run covers one window. Values under 5m are raised to 5m, the Sentinel minimum (the query still bins by the behavior's window). Rules without a window use 1h |
| `severity` | low → Low, medium → Medium, high → High, critical → **High** (Sentinel has no Critical level; the ABM severity is stated in the description) |
| `status` | `Available`. Sentinel template status is service-managed (Installed / Available / NotAvailable) and can't hold experimental / test / stable, so the ABM status goes in the description. Deprecated behaviors are left out, as with `abm compile` |
| `tactics`, `relevantTechniques` | `attack_bridge`. Sentinel only accepts ATT&CK here; tactics come from `ATTACK_TACTICS` in `compilers/sentinel.py`. Most behaviors (129 of 143 today) have no `attack_bridge`, so their rules have empty ATT&CK fields. Their ATLAS IDs are still in custom details |
| `entityMappings` | principal_id (or session_id if there is no principal) → Account, client_ip / ip → IP, client_host → Host. Threshold rules map from `group_by`; per-event rules from the event fields. Rules whose rows have none of these fields (24 today: model registry, pipeline and dataset events) get no entities |
| `customDetails` | BehaviorId, AtlasTechnique (primary), AtlasTechniques (all), AtlasTactics (comma-separated), ResponsePlan (JSON) |
| `eventGroupingSettings` | `AlertPerResult`: one alert per event or per window/group, like `abm replay` |

## 1. Create the tables and DCRs

Sentinel custom-log tables must end in `_CL`. The sentinel profile maps each source to its own table, for
example `llm_gateway` → `AIGatewayLogs_CL`. `identity` and `cloud_audit` also get custom tables
(`AIIdentityEvents_CL`, `AICloudAuditEvents_CL`), because the behaviors read normalized fields that the built-in
SigninLogs / AzureActivity tables don't have. Sentinel rejects a rule whose query uses a column that doesn't exist.

Each `DataCollection/<Table>_CL.json` creates three things: the table, a shared data collection endpoint
(`abm-ingestion`), and a DCR. The DCR takes normalized events as ABM reads them (snake_case, `timestamp`) and writes
them to the table's columns (PascalCase, `TimeGenerated`). Column types come from the fixtures and from how the
detections use each field. Deploy all of them **before** you enable the rules:

```powershell
Get-ChildItem integrations/sentinel/DataCollection/*.json | ForEach-Object {
  az deployment group create -g <workspace-rg> -n $_.BaseName --template-file $_.FullName `
    --parameters workspaceName=<workspace>
}
```

The outputs of each deployment (`logsIngestionEndpoint`, `dataCollectionRuleImmutableId`, `streamName`) are what
your sender needs. Whatever sends the events (gateway, collector, function) needs the
**Monitoring Metrics Publisher** role on the DCR.

## 2. Install the analytic rules

- **As a Content Hub solution:** package the folder with Microsoft's tool (see *Build and package*) and deploy
  `Package/mainTemplate.json`. The rules then show up under *Analytics → Rule templates*.
- **Without packaging:** import the YAML files from *Analytics → Import*, or deploy them with your own
  Sentinel-as-code pipeline.

Enable the rules you want. Per-event rules (signature, field_match) run every hour by default; threshold rules run
once per detection window.

## 3. Playbook

`Playbooks/ABM-ResponsePlan/azuredeploy.json` is a Logic App with the Microsoft Sentinel **alert** trigger. It works
the same way as the XSOAR playbook:

1. **Read the plan:** parse the alert's custom details and turn `ResponsePlan` back into the plan rows
   (`action`, `params`, `requires_approval`, `reversible`, `blast_radius`, `status`). `{{field}}` templates are
   already filled in from the alert's columns.
2. **Go through the steps one at a time:**
   - `auto`: run it right away.
   - `awaiting_approval`: send an Outlook approval email (`ApproverEmail`) first. The step runs only after
     **Approve**. Reject, no answer before `ApprovalTimeout` (default 24h), or a failed email all mean the step
     doesn't run, and it is recorded as `rejected(<decision>)`.
3. **Run the action:** a Switch with one case per `ACTION_REGISTRY` name (`rate_limit`, `revoke_token`,
   `block_deploy`, ...). By default every case POSTs `{action, params, plan_row, behavior_id, alert}` to
   `ActionEndpointUrl` with a managed-identity token for `ActionEndpointAudience`. Where you have a native connector
   (for example Microsoft Entra ID for `revoke_token`), put it in that case instead. Unknown actions are recorded as
   `failed(unknown action)`.
4. **Close out:** the results (`executed`, `failed(<status>)`, `rejected(...)`) are added to the incident as an
   HTML comment.

After deployment:

- Authorize the `office365-ABM-ResponsePlan` API connection.
- Give the playbook's managed identity the **Microsoft Sentinel Responder** role on the workspace, so it can
  comment on incidents.
- Allow that identity on your action endpoint.
- Create an automation rule with trigger *When alert is created*, limited to the ABM analytic rules, and action
  *Run playbook* `ABM-ResponsePlan`.

If you use Teams for approvals instead of Outlook, replace `Send_approval_email` with *Post adaptive card and wait for
a response*. `Set_decision_from_approver` has to set `Decision` to `Approve` for the step to run.

## 4. Run it

Send one fixture through the ingestion API and wait for the rule's next run. Fixture timestamps are fixed past dates,
so move them to the current time first:

```powershell
python -c "import json,sys,datetime as d; ev=[json.loads(l) for l in open(sys.argv[1],encoding='utf-8') if l.strip() and not l.startswith('#')]; ts=[d.datetime.fromisoformat(e['timestamp'].replace('Z','+00:00')) for e in ev]; s=d.datetime.now(d.timezone.utc)-max(ts); [e.update(timestamp=(t+s).isoformat()) for e,t in zip(ev,ts)]; json.dump(ev,open('events.json','w',encoding='utf-8'))" tests/fixtures/pi_direct_attack.jsonl

$o = az deployment group show -g <workspace-rg> -n AIGatewayLogs_CL --query properties.outputs | ConvertFrom-Json
$token = az account get-access-token --resource https://monitor.azure.com --query accessToken -o tsv
Invoke-RestMethod -Method Post -ContentType "application/json" -InFile events.json -Headers @{ Authorization = "Bearer $token" } `
  -Uri "$($o.logsIngestionEndpoint.value)/dataCollectionRules/$($o.dataCollectionRuleImmutableId.value)/streams/$($o.streamName.value)?api-version=2023-01-01"
```

Within one rule period (1h for BHV-PI-001), you should see an alert named `BHV-PI-001: ...` with the custom details
listed above, and the playbook run. One request can carry up to 1 MB; split bigger files.

Run the same fixture locally first with `abm replay --fixture tests/fixtures/pi_direct_attack.jsonl --respond`. The
dry-run plan it prints is the `ResponsePlan` the Sentinel alert will carry.

## Rule example

```yaml
id: c963a241-b0aa-5ed1-829c-d5588cd188b5
name: 'BHV-EXF-003: High-volume systematic inference queries consistent with model extraction'
severity: High
status: Available
requiredDataConnectors: []
queryFrequency: 1h
queryPeriod: 1h
triggerOperator: gt
triggerThreshold: 0
tactics:
- Exfiltration
relevantTechniques:
- T1567
query: |
  AIInferenceLogs_CL
  | where TimeGenerated > ago(1h)
  | where PrincipalId !in ("sp-batch-eval", "sp-loadtest")
  | summarize RequestCount = count(), ... by PrincipalId, ModelId, bin(TimeGenerated, 1h)
  | where RequestCount > 5000 and InputEmbeddingVariance < 0.15 and DistinctSessionCount <= 2
  | extend BehaviorId = "BHV-EXF-003", AtlasTechnique = "AML.T0024.002", ...
  | extend AtlasTactics = strcat_array(AtlasTactics, ","), AtlasTechniques = "AML.T0024.002,AML.T0040"
  | extend ResponsePlan = tostring(pack_array(
      bag_pack("action", "rate_limit", "params", bag_pack("principal", coalesce(tostring(PrincipalId), "{{principal_id}}"), ...), ...),
      ...
      bag_pack("action", "revoke_token", ..., "requires_approval", true, ..., "status", "awaiting_approval")))
entityMappings:
- entityType: Account
  fieldMappings:
  - identifier: Name
    columnName: PrincipalId
customDetails:
  BehaviorId: BehaviorId
  AtlasTechnique: AtlasTechnique
  AtlasTechniques: AtlasTechniques
  AtlasTactics: AtlasTactics
  ResponsePlan: ResponsePlan
eventGroupingSettings:
  aggregationKind: AlertPerResult
version: 1.0.0
kind: Scheduled
```

## Build and package

```bash
abm sentinel-build                 # regenerate this folder (also removes rules of deleted behaviors)
abm sentinel-build --check         # CI: exit 1 if the folder is out of date
abm sentinel-validate              # local checks: rule fields and limits, columns vs. table schemas, ARM basics
abm compile --target sentinel      # just the rules, into dist/sentinel/
abm compile --target kql --profile sentinel   # plain KQL against the _CL tables
```

`sentinel-validate` checks each rule against the Scheduled-template constraints: GUID id; severity; 5m–14d
period with frequency ≤ period; ATT&CK tactic names; techniques consistent with tactics; query ≤ 10,000 characters;
≤ 10 entity mappings with known identifiers; ≤ 20 custom details; every mapped column produced by the query or
present in the table. It also checks that each rule's table is defined in `DataCollection/`, that the data file
lists exactly the rules present, and that the playbook routes exactly the `ACTION_REGISTRY` actions. On ARM templates
it runs a few arm-ttk rules (unused parameters/variables, location parameter, blank values, hardcoded endpoints).
Those are only for fast feedback; the **sentinel-package** CI job runs the real tools:

1. Copies this folder to `Azure-Sentinel/Solutions/ATLASBehaviorMap/`.
2. Runs Microsoft's packaging tool (`Tools/Create-Azure-Sentinel-Solution/V3/createSolutionV3.ps1`) on `Data/`,
   which builds `Package/mainTemplate.json` and `createUiDefinition.json`.
3. Runs **arm-ttk** (`Test-AzTemplate`) on the package, the playbook and the DataCollection templates.
4. Uploads `Package/` as a build artifact.

To run it locally you need PowerShell 7 and clones of `Azure/Azure-Sentinel` and `Azure/arm-ttk`. Follow the steps in
`.github/workflows/ci.yml`.

To publish through the Azure-Sentinel repo, open a PR with the folder under `Solutions/`. Microsoft's own validations
(KQL against schema, template checks) run on that PR.

## Known limitations

- **Window alignment.** `bin(TimeGenerated, <window>)` uses fixed clock boundaries, and a scheduled run covers the
  last window, not a whole aligned bin. A burst that spans a bin boundary splits into two bins and can stay under
  the threshold. `abm replay` has the same tumbling-window semantics; only the run timing differs.
- **Ingestion delay.** Events that arrive after the run that covers their time range are never evaluated. If your
  pipeline lags, give the rules a longer `queryPeriod` than `queryFrequency` after importing them.
- **Reserved column names.** `sentinel-validate` rejects the column names Log Analytics reserves (`id`, `Type`,
  `TenantId`, ...). `AIRetrievalLogs_CL` has a `SourceSystem` column (BHV-COL-001 `dcount(source_system)`).
  `SourceSystem` is a standard column in many built-in tables. If the table deployment rejects it, rename the field.
- **Rule version.** Content Hub offers an update only when `version` goes up. It is fixed at `1.0.0` in
  `compilers/sentinel.py`; bump `RULE_VERSION` when rule logic changes.

Code: `src/abm/compilers/sentinel.py` (rules), `src/abm/sentinel_solution.py` (tables, DCRs, workbook, playbook,
packaging data, validation); tests in `tests/test_sentinel.py`.
