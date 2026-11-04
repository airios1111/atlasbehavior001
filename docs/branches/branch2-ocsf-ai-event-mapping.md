# Branch 2: OCSF AI-event mapping

**Branch:** `feature/branch2-ocsf-ai-event-mapping`
**Base:** `main` at the baseline of the uploaded project (143 behaviors, ATLAS 5.6.0, 64 tests)
**Roadmap item closed:** "OCSF AI-event extension mapping"

## 1. Analysis of the starting point

| Area | State before this branch | Consequence for the design |
|---|---|---|
| Input | `abm replay` reads only normalized JSONL (`engine.load_events`). The README lists the normalizer as *planned*. | Add an adapter in front of the engine. The engine, behaviors and compilers stay unchanged. |
| Sources | 12 telemetry sources, the keys of `compilers.common.KQL_TABLES` / `SPL_SOURCES`. | One inbound table per source, and a test that the key sets are equal. |
| Field contract | Behaviors declare fields per source in `telemetry.required/optional`: 186 distinct field names, 237 (source, field) pairs including `timestamp`. | The contract is the declared fields. A test requires an OCSF path for every one. |
| Alerts | `response.Alert`: behavior, severity, primary technique, tactics, context, metrics, evidence, window. | Outbound maps this to a Detection Finding without loss. `alert_from_finding()` proves it. |
| ATLAS | Techniques carry a `relationship` (primary/secondary/precondition). There is an optional `attack_bridge` to ATT&CK. | `attacks[]` cannot hold the relationship, so ATLAS goes in an extension object. `attacks[]` carries the ATT&CK bridge. |
| Fixtures | 284 native fixture files, with an attack and a benign fixture for every behavior. | Reuse them: the OCSF fixtures are generated from native ones, so parity is testable. |
| Line endings | Most tracked files are CRLF; newer files are LF. | Modified files keep CRLF. Hashes and comparisons normalize CRLF. |

## 2. OCSF release check (done before any design)

The latest release I could verify is OCSF 1.8.0 (full details and evidence are in
[`docs/ocsf.md` §1](../ocsf.md#1-ocsf-release-check-what-was-already-in-ocsf)). It already has:

* the **`ai_operation` profile**, which puts `ai_model` and `message_context` on API Activity,
  Datastore Activity and Process Activity;
* **`ai_model`**: `name`, `uid`, `version`, `ai_provider`;
* **`message_context`**: `uid`, `name`, `service`, `application`, `ai_role_id`, and
  **`prompt_tokens` / `completion_tokens` / `total_tokens`**;
* `database.embedding_model` and `database.type_id` = Vector;
* the `attack` object, whose 1.8.0 description names both ATT&CK and ATLAS.

So `model_id`, `session_id` and the token counts are **not** in the extension. They map to the
core attributes. The extension adds attributes to `ai_model` and `message_context` and introduces
new objects only where OCSF has nothing.

## 3. Plan and status

| # | Task | Deliverable | Status |
|---|---|---|---|
| 1 | Vendor the OCSF 1.8.0 core slice and make it reproducible | `schemas/ocsf/base/`, `scripts/ocsf_vendor_base.py` | done |
| 2 | abm extension: `extension.json`, `dictionary.json`, `objects/`, class patches | `schemas/ocsf/abm-extension/` | done |
| 3 | Schema model and validator (extension self-check, event validation, path resolution) | `src/abm/ocsf_schema.py` | done |
| 4 | Inbound per-source tables for all 12 sources; source detection; placeholder handling | `src/abm/ocsf.py` (`SOURCES`, `normalize`, `load_ocsf_events`) | done |
| 5 | Outbound Detection Finding with ATLAS in `atlas_mapping` (extension) | `to_detection_finding`, `alert_from_finding` | done |
| 6 | CLI: `abm replay --input-format ocsf --output-format ocsf` (+ `--ocsf-source`, `--ocsf-atlas-in-attacks`, `--validate-ocsf`) | `src/abm/cli.py` | done |
| 7 | One OCSF fixture per source + HTTP Activity variant + manifest | `tests/fixtures/ocsf/`, `scripts/gen_ocsf_fixtures.py` | done |
| 8 | Tests: round trip (same alerts as the native JSONL), full corpus, validity, CLI | `tests/test_ocsf.py` (88 tests) | done |
| 9 | Docs and tooling: design, generated mapping reference, README, Makefile, CI checks for the generated files plus an OCSF replay smoke test | `docs/ocsf.md`, `docs/ocsf-mapping.md`, `.github/workflows/ci.yml` | done |
| 10 | Upstream guard for future OCSF releases | `scripts/ocsf_check_upstream.py` | done |
| 11 | Verification script + reference output to diff with local runs | `scripts/verify_branch2.{py,ps1,sh}`, `verification/branch2/expected/` | done |

## 4. Design decisions

1. **Core first, then extend core objects, then new objects, then `unmapped`.**
   * 71 of 225 field mappings land on OCSF core attributes.
   * 148 go through extension attributes: 11 new objects, plus attributes added to `ai_model`,
     `message_context` and four classes.
   * 5 generic enrichment flags stay in OCSF's `unmapped`.
2. **ATLAS in the extension.** `atlas_mapping` keeps the ATLAS version, the primary technique, every
   technique with its relationship, and the tactics and mitigations. `attacks[]` holds the ATT&CK
   bridge. OCSF 1.8.0 does allow ATLAS in `attacks[]`, so `--ocsf-atlas-in-attacks` adds it for
   consumers that want it.
3. **Source detection** uses `metadata.log_name` first. If that is missing, it picks the source whose
   mapped paths best cover the event, with `ai_role_id` breaking ties. `--ocsf-source` forces a
   source.
4. **Placeholders.** OCSF-required values that a source doesn't observe are written and listed in
   `metadata.tags` so that `normalize()` never reads them back as data.
5. **No engine or behavior changes.** The adapter is a pure function on each side of the engine.

## 5. Verification

```powershell
.\scripts\verify_branch2.ps1          # Windows
./scripts/verify_branch2.sh           # Linux/macOS
python scripts/verify_branch2.py      # any OS, inside the venv
```

These write `reports/verify-branch2/{report.txt, alerts.jsonl, findings.jsonl, normalized.jsonl, mapping.tsv}`
and compare them with `verification/branch2/expected/`. `RESULT: identical to the reference output`
means your checkout behaves exactly like the reference run. `environment.txt` records the
Python, platform and git state and is not compared.

## 6. Commits

1. `ocsf: vendor OCSF 1.8.0 base subset, add abm extension and schema validator`
2. `ocsf: per-source inbound mapping and Detection Finding output`
3. `cli: abm replay --input-format/--output-format ocsf`
4. `tests: one OCSF fixture per source and round-trip tests`
5. `docs: OCSF design, generated mapping reference, README, Makefile and CI`
6. `verify: branch2 verification scripts and reference output`
