"""Generate the OCSF test fixtures (one per telemetry source) from the native JSONL fixtures.

Each OCSF fixture is the attack fixture of one representative behavior, wrapped as OCSF 1.8.0
events by abm.ocsf.to_ocsf_event. tests/fixtures/ocsf/MANIFEST.json records which native fixture
and behavior each file came from; tests/test_ocsf.py replays both and requires identical alerts.

    python scripts/gen_ocsf_fixtures.py          # (re)write tests/fixtures/ocsf/
    python scripts/gen_ocsf_fixtures.py --check  # exit 1 if the committed files are stale
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from abm.engine import load_events  # noqa: E402
from abm.ocsf import SOURCES, to_ocsf_event  # noqa: E402

OUT = ROOT / "tests" / "fixtures" / "ocsf"

# file stem -> (source, behavior, native fixture, class_uid)
FIXTURES: dict[str, tuple[str, str, str, int]] = {
    "llm_gateway": ("llm_gateway", "BHV-PI-001", "tests/fixtures/pi_direct_attack.jsonl", 6003),
    "inference_gateway": ("inference_gateway", "BHV-EV-001", "tests/fixtures/ev_adversarial_attack.jsonl", 6003),
    "inference_gateway.http": ("inference_gateway", "BHV-EV-001", "tests/fixtures/ev_adversarial_attack.jsonl", 4002),
    "llm_retrieval": ("llm_retrieval", "BHV-PI-002", "tests/fixtures/pi_indirect_attack.jsonl", 6005),
    "vector_store": ("vector_store", "BHV-PO-004", "tests/fixtures/pack/po004_attack.jsonl", 6005),
    "agent_memory": ("agent_memory", "BHV-PO-006", "tests/fixtures/pack/po006_attack.jsonl", 6005),
    "agent_runtime": ("agent_runtime", "BHV-AG-001", "tests/fixtures/ag_out_of_scope.jsonl", 6003),
    "mcp_gateway": ("mcp_gateway", "BHV-LM-001", "tests/fixtures/pack/lm001_attack.jsonl", 6003),
    "model_registry": ("model_registry", "BHV-SC-001", "tests/fixtures/sc_unsigned_load.jsonl", 6003),
    "ml_workspace": ("ml_workspace", "BHV-SC-004", "tests/fixtures/pack/sc004_attack.jsonl", 6003),
    "training_pipeline": ("training_pipeline", "BHV-PO-001", "tests/fixtures/po_drift_attack.jsonl", 6003),
    "cloud_audit": ("cloud_audit", "BHV-COL-004", "tests/fixtures/pack/col004_attack.jsonl", 6003),
    "identity": ("identity", "BHV-LM-002", "tests/fixtures/pack/lm002_attack.jsonl", 3002),
}


def _sha(text: str) -> str:
    return hashlib.sha256(text.replace("\r\n", "\n").encode("utf-8")).hexdigest()


def render() -> dict[str, str]:
    files: dict[str, str] = {}
    manifest: dict[str, dict] = {}
    for stem, (source, behavior, native, class_uid) in FIXTURES.items():
        events = load_events(ROOT / native)
        lines = [json.dumps(to_ocsf_event(e, source, class_uid), ensure_ascii=False) for e in events]
        body = "\n".join(lines) + "\n"
        name = f"{stem}.ocsf.jsonl"
        files[name] = body
        manifest[name] = {"source": source, "class_uid": class_uid, "behavior": behavior,
                          "native_fixture": native, "events": len(events), "sha256": _sha(body)}
    missing = set(SOURCES) - {v["source"] for v in manifest.values()}
    if missing:
        raise SystemExit(f"no OCSF fixture for source(s): {sorted(missing)}")
    files["MANIFEST.json"] = json.dumps(manifest, indent=2) + "\n"
    return files


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--check", action="store_true", help="verify committed fixtures are current")
    a = p.parse_args()
    files = render()
    if a.check:
        stale = [n for n, body in files.items()
                 if not (OUT / n).is_file() or _sha((OUT / n).read_text(encoding="utf-8")) != _sha(body)]
        extra = sorted(f.name for f in OUT.glob("*") if f.name not in files) if OUT.is_dir() else []
        for n in stale:
            print(f"stale: tests/fixtures/ocsf/{n}")
        for n in extra:
            print(f"unexpected: tests/fixtures/ocsf/{n}")
        print("OCSF fixtures up to date" if not (stale or extra) else "run: python scripts/gen_ocsf_fixtures.py")
        return 1 if stale or extra else 0
    OUT.mkdir(parents=True, exist_ok=True)
    for n, body in files.items():
        (OUT / n).write_text(body, encoding="utf-8", newline="\n")
    print(f"wrote {len(files) - 1} OCSF fixture(s) + MANIFEST.json -> {OUT.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
