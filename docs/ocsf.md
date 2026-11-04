# OCSF AI-event mapping

`abm replay` can read OCSF events and write OCSF Detection Findings. Behaviors don't change: the
adapter turns OCSF input into the same normalized fields the YAML detections already read, and
turns each alert into an OCSF 1.8.0 Detection Finding.

```
OCSF 1.8.0 event ──normalize()──► normalized event ──Engine──► Alert ──to_detection_finding()──► OCSF Detection Finding (2004)
 (API / HTTP / Datastore /         (principal_id, session_id,                                  (ATLAS in the abm extension,
  Authentication Activity)          tool_in_scope, ...)                                         ATT&CK bridge in attacks[])
```

* Code: `src/abm/ocsf.py` (mapping tables, inbound, outbound) and `src/abm/ocsf_schema.py`
  (schema model and validator).
* Extension: `schemas/ocsf/abm-extension/` (OCSF source layout).
* Vendored OCSF core slice: `schemas/ocsf/base/ocsf-1.8.0-subset.json`.
* Per-source mapping tables: [`docs/ocsf-mapping.md`](ocsf-mapping.md) (generated).

## 1. OCSF release check: what was already in OCSF

Before designing anything I checked the current OCSF release for AI and LLM objects.

| Item | Result |
|---|---|
| Latest release I could verify | **OCSF 1.8.0**. The compiled export `schema.ocsf.io/1.8.0/export/v2/schema` is bundled in the `ocsf-json-schema` 1.2.0 wheel on PyPI (sha256 `221b43d0…d6d91f82`, recorded in the vendored file). `ocsf-mapper` 0.4.4 (June 2026) pins 1.8.0 and tracks `1.9.0-dev` as the development line. The sandbox could not reach schema.ocsf.io or GitHub directly. Re-run the check with `python scripts/ocsf_check_upstream.py` wherever schema.ocsf.io is reachable. |
| AI objects in 1.5.0, 1.6.0, 1.7.0 | None. |
| **`ai_operation` profile** (new in 1.8.0) | Adds `ai_model` and `message_context` to **API Activity (6003)**, **Datastore Activity (6005)** and **Process Activity (1007)**. |
| **`ai_model` object** | `name` (required), `ai_provider` (required), `uid`, `version`. |
| **`message_context` object** | `uid` (session/conversation id), `name`, `service` (AI service / MCP server), `application` (client app or agent), `ai_role_id` (User, Assistant, Tool, Agent, Orchestrator, Retriever), **`prompt_tokens`, `completion_tokens`, `total_tokens`**. |
| `database` object | `embedding_model`, and `type_id` 7 = Vector, 8 = Knowledge Graph. |
| `attack`, `tactic`, `technique`, `mitigation` | 1.8.0 describes them as "MITRE ATT&CK® & ATLAS™" objects, so ATLAS IDs are now *allowed* in `attacks[]`. `attacks[]` still cannot say whether a technique is primary, secondary or a precondition. It also has only one free-text `version` per entry, so a consumer can only tell ATT&CK and ATLAS apart by ID prefix. |

**What this changed in the design:** the extension doesn't define anything for model ID, session ID
or token counts. Those already exist in OCSF 1.8.0, so the extension only adds attributes to the
core `ai_model` and `message_context` objects:

| Concept from the brief | Where it lives | Tier |
|---|---|---|
| `model_id` | `ai_model.uid` | OCSF core |
| `session_id` | `message_context.uid` (LLM/agent sessions), `actor.session.uid` (inference clients) | OCSF core |
| input / output / total tokens | `message_context.prompt_tokens` / `completion_tokens` / `total_tokens` | OCSF core |
| reasoning tokens, cost, context utilization, inter-arrival, channel | added to `message_context` | abm patch of a core object |
| model tier, environment | added to `ai_model` | abm patch of a core object |
| `prompt_hash`, prompt text and lexical signals | `ai_prompt` | abm object |
| `tool_name`, args, output, scope, approval, MCP trust facts | `ai_tool_call` | abm object |
| agent ID / MCP server | `message_context.application.uid` / `message_context.service.uid` | OCSF core |

## 2. The abm extension

`schemas/ocsf/abm-extension/` uses the OCSF source layout. A file whose `extends` names a core
definition and that has no `name` is a patch of that definition. This is the same convention the
OCSF server, `ocsf-lib` and `ocsf-validator` use.

```
extension.json            name "abm", uid 900 (unregistered, private range), version 0.1.0
dictionary.json           151 attributes: only names not already in the OCSF core dictionary
objects/
  ai_model.json           patch  + tier, environment
  message_context.json    patch  + reasoning_tokens, cost_usd, context_utilization, inter_arrival_s, channel
  ai_prompt.json          prompt content, prompt_hash, user_content, lexical/adversarial-suffix signals
  ai_completion.json      completion content, refused, citations, memorization score
  ai_guardrail.json       verdicts and scores from guardrails, moderation and adversarial/trigger/deepfake detectors
  ai_tool_call.json       agent / MCP tool invocation + authorization and enrichment facts
  ai_context_record.json  RAG document, vector-store record or agent-memory entry, with provenance and trust
  ai_artifact.json        model / dataset / package / container image: provenance, integrity, scan results
  ai_inference.json       predictive / multimodal inference request characteristics
  ai_training.json        training, fine-tuning or data-pipeline job
  atlas_mapping.json      ATLAS version, tactics[], technique (primary), techniques[], mitigations[]
  atlas_technique.json    extends core `technique` + atlas_relationship (primary|secondary|precondition)
  ai_response_action.json planned countermeasure: action, params, approval gate, blast radius, status
events/
  application/api_activity.json        patch + ai_prompt, ai_completion, ai_guardrail, ai_tool_call, ai_artifact, ai_inference, ai_training
  application/datastore_activity.json  patch + ai_context_record, ai_guardrail
  network/http_activity.json           patch + ai_model, message_context, ai_prompt, ai_completion, ai_guardrail, ai_inference
  findings/detection_finding.json      patch + atlas_mapping, response_plan, ai_model
```

Naming rules, all enforced by `OcsfSchema.check_extension()` in the tests:

* No extension attribute redefines a core dictionary name. Objects reuse core attributes (`uid`,
  `name`, `desc`, `url`, `version`, `tactics`, `technique`, `classification`) with their core
  meaning.
* Identifiers end in `_uid`, because OCSF reserves `_id` for enum siblings. That is why `doc_id`
  becomes `ai_context_record.uid`, `job_id` becomes `ai_training.job_uid`, and so on.
* Every dictionary attribute is used by at least one object or class patch.

The extension is validated structurally in CI (see §5). To validate it with the official tooling,
copy the folder into an OCSF schema checkout at the matching tag
(`ocsf-schema/extensions/abm/`) and run `ocsf-validator` (`pip install ocsf-validator`). The
branch verification script prints the exact commands.

## 3. Inbound: OCSF events to normalized fields

`SOURCES` in `src/abm/ocsf.py` has one table per telemetry source, covering the same 12 keys as
`KQL_TABLES`:

| Source | OCSF class |
|---|---|
| `llm_gateway` | API Activity 6003 (also HTTP Activity 4002) |
| `inference_gateway` | API Activity 6003 (also HTTP Activity 4002) |
| `llm_retrieval`, `vector_store`, `agent_memory` | Datastore Activity 6005 |
| `agent_runtime`, `mcp_gateway`, `model_registry`, `ml_workspace`, `training_pipeline`, `cloud_audit` | API Activity 6003 |
| `identity` | Authentication 3002 |

Every field that any behavior declares in `telemetry.required` or `telemetry.optional` has a path
(a test enforces this). Across all sources there are 225 field mappings: 71 land on OCSF core
attributes, 148 go through extension attributes, 5 are generic enrichment flags kept in OCSF's own
`unmapped` object (`workload_registered`, `deployer_in_approved_group`, `scope`,
`device_fingerprint`, `sign_in_asn_seen_before`) and 1 is an alias (`identity.asn` → `client_asn`).

How an event's source is chosen:

1. `--ocsf-source` / `normalize(ev, source=...)` if given.
2. `metadata.log_name` (or `metadata.log_source`) equal to a source key.
3. Otherwise, the source whose mapped paths cover the most attributes in the event, with the
   `message_context.ai_role_id` as a tie-breaker. On every fixture in the repository this picks the
   right source even with `log_name` removed (tested).

Other rules:

* `timestamp` comes from `time_dt` when present, otherwise from `time` (epoch ms, formatted as
  ISO 8601 `Z`).
* Attributes in `unmapped` come back under their own name. That keeps extra source fields
  (for example `has_emoji` in a fixture) lossless.
* `to_ocsf_event()` sometimes has to write a value OCSF requires but the source never provided
  (`api.operation`, `ai_model.ai_provider`, `src_endpoint.svc_name`, and so on). It lists those
  paths in `metadata.tags[name="abm.placeholder_attributes"]`, and `normalize()` ignores them.
  Real producers don't set this tag, so every attribute they send is read.
* Null values are omitted on output, as OCSF expects. The engine treats a missing field and a null
  field the same way.

## 4. Outbound: alerts to Detection Findings

`abm replay --output-format ocsf` writes one OCSF Detection Finding (class 2004, `type_uid`
200401) per alert:

| Finding attribute | Content |
|---|---|
| `finding_info.uid` / `metadata.uid` | deterministic UUIDv5 of behavior, window, context and technique |
| `finding_info.analytic` | `uid` = behavior ID, `type_id` from the detection logic (signature → 8 Regular Expressions, field_match → 1 Rule, windowed_threshold → 3 Statistical), `state_id` from the behavior status |
| `severity_id`, `confidence_id` | from behavior severity and confidence |
| **`atlas_mapping`** (abm) | ATLAS data version, primary `technique`, every technique with `atlas_relationship`, tactics, mitigations, each with its name and `src_url` |
| `attacks[]` | the behavior's `attack_bridge` ATT&CK techniques (sub-techniques split into `technique` + `sub_technique`). With `--ocsf-atlas-in-attacks`, ATLAS techniques are added too (OCSF 1.8.0 allows it) |
| `actor`, `ai_model` | principal, session and model from the alert context |
| `evidences[0].data` | full alert context, metrics, matched evidence and window start. `alert_from_finding()` rebuilds the alert from this without loss (tested) |
| `remediation` | ATLAS mitigations and response actions in text, with mitigation URLs |
| `response_plan` (abm) | with `--respond`: each planned action with its approval gate and status |

## 5. CLI

```bash
abm replay --fixture events.ocsf.jsonl --input-format ocsf                 # OCSF in, native alerts out
abm replay --fixture events.jsonl --output-format ocsf                     # native in, Detection Findings out
abm replay --fixture events.ocsf.jsonl --input-format ocsf --output-format ocsf --validate-ocsf --respond
abm replay --fixture gw.json --input-format ocsf --ocsf-source llm_gateway # force the mapping table
abm replay ... --output-format ocsf --ocsf-atlas-in-attacks                # ATLAS also in attacks[]
```

OCSF input can be JSON Lines or a single JSON array. `--validate-ocsf` checks input and output
events against the vendored OCSF 1.8.0 core plus the abm extension. Errors go to stderr and the
exit code is 2. Without the flag, mapping is lenient.

## 6. Tests and fixtures

* `tests/fixtures/ocsf/<source>.ocsf.jsonl`: one fixture per source (12), plus
  `inference_gateway.http.ocsf.jsonl` for HTTP Activity. They are generated by
  `scripts/gen_ocsf_fixtures.py` from a representative behavior's native attack fixture, and
  `MANIFEST.json` records which one.
* `tests/test_ocsf.py`:
  * extension consistency;
  * every declared field is mapped;
  * every mapping path resolves in OCSF + extension;
  * each fixture is valid OCSF, normalizes back to its native fixture, and **raises the same alerts
    as the native JSONL fixture**;
  * source detection works without `log_name`;
  * the full round trip over all 159 behaviors × both fixtures gives identical alerts and
    unchanged test expectations;
  * time-only producers alert the same way;
  * the Detection Finding is valid and round-trips to the alert;
  * CLI end to end.

## 7. Limitations and next steps

* The extension UID 900 is unregistered. Register `abm` with OCSF, or change the UID to fit your
  private range, before shipping events to a shared data lake.
* Process Activity (1007) also carries the `ai_operation` profile. Mapping agent shell tools from
  EDR process events (`process.cmd_line` → `tool_args`) is a natural next table. It isn't included
  because no current behavior needs it.
* Enrichment-only facts such as `inter_arrival_s`, `server_first_seen_for_agent` and
  `source_domain_age_days` live on the AI objects they describe. OCSF `enrichments[]` would also
  work, but its values are strings.
* The KQL/SPL compilers still target the normalized column names. Compiling directly against OCSF
  tables such as Security Lake or Sentinel ASIM is a separate change.
