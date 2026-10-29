# Cortex XSOAR integration

`abm replay --xsoar <url>` creates **one Cortex XSOAR incident per alert**. Each incident carries the ATLAS
mapping, the evidence and the full response plan, and XSOAR runs the response:

```
abm replay ──► POST /incident ──► XSOAR incident "AI Security Alert" ──► playbook
                                    ├─ labels: behavior_id, atlas_technique, atlas_tactic, context.*, planned_action
                                    ├─ CustomFields: abmbehaviorid, abmatlastechnique, abmatlastactics, abmresponseplan
                                    └─ rawJSON: {"alert": {...}, "response_plan": [...]}
```

ABM never executes actions itself in this mode. Each action's status shows where it went:

| Plan status | Reported status | Meaning |
|---|---|---|
| `auto` | `delegated(xsoar:<incident id>)` | Playbook may run it automatically |
| `awaiting_approval` | `awaiting_approval(xsoar:<incident id>)` | Playbook must route it to an analyst task |
| (HTTP error) | `failed(<reason>)` | Incident was not created; nothing ran |

## 1. Create an API key

- **XSOAR 6 (on-prem):** Settings → Integrations → API Keys → *Get Your Key*.
- **XSOAR 8 / Cortex cloud:** Settings → Configurations → API Keys → *New Key* (Standard). Note the key **ID**.
  Use the tenant's **API URL** (`https://api-<tenant>...`) shown under *Copy API URL*.

Give the key a role that can create incidents and nothing more.

## 2. Create the incident type and fields

In XSOAR, create incident type **`AI Security Alert`**. If you use another name, pass it with
`--xsoar-incident-type`. Then create these incident fields (Settings → Objects setup → Incidents → Fields) and
associate them with that type. The *machine names* (cliName) must match exactly:

| Field name | Machine name | Type |
|---|---|---|
| ABM Behavior ID | `abmbehaviorid` | Short text |
| ABM ATLAS Technique | `abmatlastechnique` | Short text |
| ABM ATLAS Tactics | `abmatlastactics` | Short text |
| ABM Response Plan | `abmresponseplan` | Long text (JSON) |

If the fields don't exist, XSOAR drops the `CustomFields` but keeps the labels and `rawJSON`, so a mapper can
still read everything.

## 3. Playbook

Create a playbook on the `AI Security Alert` type that keeps the approval gate ABM defined:

1. **Parse plan:** `ParseJSON` (or a short automation) on `${incident.abmresponseplan}` (or `rawJSON.response_plan`).
2. **Loop over actions:** for each action, branch on `status`:
   - `auto`: run the matching command (block, rate-limit, notify, open ticket). Map ABM action names to your
     integrations, e.g. `rate_limit` → API gateway policy, `revoke_token` → identity provider,
     `block_deploy` → registry / CI.
   - `awaiting_approval`: create a **manual task / data-collection approval** first, and run the command only
     when it's approved.
3. **Close-out:** record executed actions back to the incident (`setIncident`) for audit.

`requires_approval`, `reversible` and `blast_radius` for every action are included in each plan row, so the
playbook can apply its own policy as well.

## 4. Run it

PowerShell (keys only in environment variables, never on the command line):

```powershell
$env:XSOAR_API_KEY = "<api key>"
$env:XSOAR_API_KEY_ID = "<key id>"       # XSOAR 8 / cloud only; leave unset for XSOAR 6
abm replay --fixture tests/fixtures/pi_direct_attack.jsonl --behavior BHV-PI-001 --xsoar https://api-<tenant>.example.com
```

| XSOAR version | Endpoint used | Auth headers |
|---|---|---|
| 6 (no key ID) | `POST <url>/incident` | `Authorization: <key>` |
| 8 / cloud (key ID set) | `POST <url>/xsoar/public/v1/incident` | `Authorization: <key>`, `x-xdr-auth-id: <id>` |

Only `https://` URLs are accepted. To try it without a tenant, run the same command with `--respond` instead of
`--xsoar`. That gives you the dry-run plan.

## Payload example

```json
{
  "name": "[BHV-PI-001] Instruction-override pattern in direct user input",
  "type": "AI Security Alert",
  "severity": 3,
  "occurred": "2026-10-01T14:00:30Z",
  "details": "Instruction-override pattern...\nATLAS AML.T0051.000 (AML.TA0005)\nEvidence:\n- prompt =~ ...",
  "labels": [{"type": "behavior_id", "value": "BHV-PI-001"}, {"type": "atlas_technique", "value": "AML.T0051.000"}],
  "CustomFields": {"abmbehaviorid": "BHV-PI-001", "abmatlastechnique": "AML.T0051.000",
                   "abmatlastactics": "AML.TA0005", "abmresponseplan": "[...]"},
  "rawJSON": "{\"alert\": {...}, \"response_plan\": [...]}",
  "createInvestigation": true
}
```

Severity mapping: low → 1, medium → 2, high → 3, critical → 4.

Code: `XsoarExecutor` in `src/abm/response.py`; tests in `tests/test_xsoar.py`.
