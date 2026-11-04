# Behavior Authoring

One YAML file per behavior under `behaviors/<category>/<ID>.yaml`. The file is the contract:
detections, coverage and response plans are all generated from it.

## Required fields

| Field | Rule |
|---|---|
| `id` | `BHV-<PREFIX>-NNN`; prefix from PI, JB, LK, EXF, EV, PO, SC, BD, AG, DOS, CH (attack categories) or RC, MA, CA, LM, C2, COL, RD (tactic categories: recon, model access, credential access, lateral movement, command and control, collection, resource development) |
| `status` | `experimental` → `test` → `stable` (→ `deprecated`) |
| `atlas.tactics` | `AML.TA####`, at least one |
| `atlas.techniques` | `AML.T####[.###]`, at least one with `relationship: primary`; use `precondition` for enabling access (e.g. AML.T0040) — preconditions do not count toward coverage |
| `telemetry.required[0].source` | Drives the SIEM table/index mapping in `src/abm/compilers/common.py` |
| `detection.logic` | `signature` \| `windowed_threshold` \| `field_match` |
| `tests` | `stable` requires at least one `alert` and one `no_alert` fixture |

## Detection logic

**signature**: regex per field; any pattern on any signature fires. Patterns must be RE2-compatible
(no look-around, no backreferences) so they compile to KQL.
Invalid regex syntax is reported during validation; review RE2 compatibility separately.

```yaml
detection:
  logic: signature
  signatures:
    - field: prompt
      patterns: ['(?i)\bignore\s+previous\s+instructions\b']
```

**windowed_threshold**: tumbling window per `group_by`; every condition must hold.
The window must be a positive integer followed by `s`, `m`, `h`, or `d` (e.g. `30s`, `15m`, `1h`).
Zero-length windows are rejected during validation.
Metrics: `count`, `dcount(f)`, `sum(f)`, `avg(f)`, `variance(f)`, `max(f)`, `min(f)`.

```yaml
detection:
  logic: windowed_threshold
  window: 1h
  group_by: [principal_id]
  metrics: { n: count, sessions: dcount(session_id) }
  conditions: ["n > 5000", "sessions <= 2"]
```

**field_match**: all keys must match.

## Match / filter operators

Used by `detection.match` and `detection.filters` (filters scope events before evaluation):

`value` (equality) · `{in: [...]}` · `{not_in: [...]}` · `{ne: x}` · `{exists: bool}` ·
`{regex: "..."}` · `{gt|gte|lt|lte: n}` (combined with AND).

## Response actions

Must exist in `ACTION_REGISTRY` (`src/abm/response.py`). Params support `{{field}}` templating from
alert context and metrics. Actions flagged `requires_approval` are never auto-executed; override per
step with `requires_approval: true|false`.

## Fixtures

Normalized JSONL, one event per line, `timestamp` (ISO-8601 or epoch) required. Every positive
fixture should have a benign near-miss twin (same shape, should not fire). Generate reproducibly in
`scripts/gen_fixtures.py` (seed set) or as a spec in `scripts/behavior_pack/` rendered by
`scripts/gen_behavior_pack.py`, which writes the YAML and both fixtures. Pass `status="experimental"`
to a spec when the detection only sees a weak downstream proxy of the technique; coverage then
scores it 1 (mitigation-only).

The engine is stateless. When a detection needs history ("first time this agent used this server",
"seconds since the previous call"), read a field computed by the normalizer or an enrichment step
and say in the description how it is computed (see `inter_arrival_s` in BHV-C2-001).

## Promotion checklist

- [ ] `abm validate --run-tests` clean
- [ ] Mapped to the most specific sub-technique
- [ ] Mitigations bound
- [ ] Compiled KQL/SPL reviewed against a real workspace
- [ ] False positives documented (`abm calibrate` lists them next to measured noise)
- [ ] Confidence calibrated from production dispositions (`abm calibrate --write`, n ≥ 20)
