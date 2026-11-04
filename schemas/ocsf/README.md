# OCSF schema files

| Path | What | How it is produced |
|---|---|---|
| `base/ocsf-1.8.0-subset.json` | Compact slice of the **OCSF 1.8.0** core schema: the event classes abm reads and writes (API, HTTP, Datastore Activity, Authentication, Detection Finding), every core object, the dictionary and the type table. Attribute descriptions are removed. | `python scripts/ocsf_vendor_base.py --export ocsf-1.8.0.json`, where the export comes from `https://schema.ocsf.io/1.8.0/export/v2/schema`. The export's sha256 is recorded in the file. |
| `abm-extension/` | The **abm** OCSF extension in OCSF source layout: `extension.json`, `dictionary.json`, `objects/`, `events/`. It adds attributes to the core `ai_model` and `message_context` objects (`ai_operation` profile, OCSF 1.8.0) and to the API, Datastore, HTTP Activity and Detection Finding classes. It adds new AI objects only where OCSF has none. | Hand-maintained. `tests/test_ocsf.py` checks it against the base: no redefined core names, every reference resolves, no unused attributes, `_uid` naming. |

Design, release check and mapping rules: [`docs/ocsf.md`](../../docs/ocsf.md). Per-source field
tables: [`docs/ocsf-mapping.md`](../../docs/ocsf-mapping.md).

## Updating to a newer OCSF release

```bash
python scripts/ocsf_check_upstream.py            # needs schema.ocsf.io; or --export <file>
python scripts/ocsf_vendor_base.py --export ocsf-<new>.json
# set OCSF_VERSION in src/abm/ocsf.py and src/abm/ocsf_schema.py, then
python scripts/gen_ocsf_fixtures.py && python scripts/gen_ocsf_mapping_doc.py && pytest -q
```

`ocsf_check_upstream.py` lists any abm extension attribute or object whose name now exists in the
OCSF core. Move those to the core definition instead of keeping a duplicate.

## Validating the extension with the official tooling

```bash
git clone --branch v1.8.0 https://github.com/ocsf/ocsf-schema
cp -r schemas/ocsf/abm-extension ocsf-schema/extensions/abm
pip install ocsf-validator
python -m ocsf_validator ocsf-schema
```
