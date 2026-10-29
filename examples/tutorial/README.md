# Tutorial: write, test and run your own behaviors

A self-contained mini-project with two example behaviors, one per detection style:

| Behavior | Logic | Fires when |
|---|---|---|
| `BHV-PI-901` | `signature` | A prompt asks the model to send/post/upload/forward something to an `http(s)://` URL |
| `BHV-CH-901` | `windowed_threshold` | One principal makes more than 100 requests **and** spends more than $5 within 10 minutes |

```
examples/tutorial/
├── behaviors/BHV-PI-901.yaml, BHV-CH-901.yaml
├── fixtures/          # pi901_*, ch901_* (attack + benign near-miss) and traffic_mixed.jsonl
├── gen_fixtures.py    # regenerates fixtures/ deterministically
└── run_tutorial.ps1   # runs every step below
```

Run everything from the repository root. `--root` points `abm` at this folder, and `--catalog` reuses
the main ATLAS catalog.

```powershell
.\.venv\Scripts\Activate.ps1
$tut = "--root", "examples/tutorial", "--catalog", "atlas/catalog.yaml"

abm @tut validate --run-tests                    # schema + ATLAS IDs + fixtures
abm @tut test                                    # 4/4 fixture tests
abm @tut replay --fixture examples/tutorial/fixtures/traffic_mixed.jsonl --respond
abm @tut compile --target all --out examples/tutorial/out/rules
abm @tut coverage --out examples/tutorial/out/reports
```

Or run all steps at once: `.\examples\tutorial\run_tutorial.ps1`

Exercise: change `spend_usd > 5` to `spend_usd > 7` in `BHV-CH-901.yaml` and re-run `abm @tut test`.
The burst fixture only spends about $6.06, so the alert test now fails. Revert the change afterwards.

The full walkthrough with expected output is in `docs/ATLAS_Behavior_Map_Code_Guide.pdf` (Tutorial section).
