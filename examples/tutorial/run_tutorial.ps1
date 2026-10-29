# Runs every step of the tutorial from the repository root.
#   .\examples\tutorial\run_tutorial.ps1
# Outputs (compiled rules, coverage reports) go to examples/tutorial/out/ (gitignored).

$ErrorActionPreference = "Stop"
$repo = Resolve-Path (Join-Path $PSScriptRoot "..\..")
Set-Location $repo

$abm = Join-Path $repo ".venv\Scripts\abm.exe"
$python = Join-Path $repo ".venv\Scripts\python.exe"
if (-not (Test-Path $abm)) { throw "abm not found. Run: python -m venv .venv; .\.venv\Scripts\pip install -e "".[dev]""" }
$tut = @("--root", "examples/tutorial", "--catalog", "atlas/catalog.yaml")

function Step($title) { Write-Host "`n=== $title" -ForegroundColor Cyan }

Step "1. Sanity check the main project"
& $abm validate --run-tests

Step "2. Replay a built-in attack (BHV-PI-001)"
& $abm replay --fixture tests/fixtures/pi_direct_attack.jsonl --behavior BHV-PI-001 --expect alert --respond

Step "3. Regenerate the tutorial fixtures"
& $python examples/tutorial/gen_fixtures.py

Step "4. Validate the tutorial behaviors and run their fixture tests"
& $abm @tut validate --run-tests
& $abm @tut test

Step "5. Replay mixed traffic and plan responses (dry run)"
& $abm @tut replay --fixture examples/tutorial/fixtures/traffic_mixed.jsonl --respond

Step "6. Compile the tutorial behaviors to SIEM rules"
& $abm @tut compile --target all --out examples/tutorial/out/rules
Get-Content examples/tutorial/out/rules/kql/BHV-CH-901.kql

Step "7. Show the ATLAS mapping and coverage"
& $abm @tut map
& $abm @tut coverage --out examples/tutorial/out/reports

Write-Host "`nDone. Next: edit examples/tutorial/behaviors/BHV-CH-901.yaml (try 'spend_usd > 7') and re-run step 4." -ForegroundColor Green
