"""Keep the tutorial in examples/tutorial/ runnable."""

import json
from pathlib import Path

from abm.cli import main

ROOT = Path(__file__).resolve().parents[1]
TUT = ROOT / "examples" / "tutorial"
ARGS = ["--root", str(TUT), "--catalog", str(ROOT / "atlas" / "catalog.yaml")]


def test_tutorial_behaviors_validate_and_pass_fixtures(capsys):
    assert main([*ARGS, "validate", "--run-tests"]) == 0
    assert "2 behavior(s), 0 error(s), 0 warning(s)" in capsys.readouterr().out


def test_tutorial_mixed_traffic_replay(capsys):
    fixture = str(TUT / "fixtures" / "traffic_mixed.jsonl")
    assert main([*ARGS, "replay", "--fixture", fixture, "--respond", "--expect", "alert"]) == 0
    alerts = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    by_id = {a["behavior_id"]: a for a in alerts}
    assert set(by_id) == {"BHV-PI-901", "BHV-CH-901"}
    assert by_id["BHV-CH-901"]["context"] == {"principal_id": "key-7731"}
    statuses = {r["action"]: r["status"] for r in by_id["BHV-PI-901"]["response"]}
    assert statuses["revoke_token"] == "awaiting_approval"  # noqa: S105 (action name, not a secret)
    assert statuses["block_request"] == "executed(dry-run)"
