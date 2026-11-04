# Branch 2 verification (Windows PowerShell). Creates .venv if needed, installs the project, runs
# scripts\verify_branch2.py and compares the results with verification\branch2\expected\.
#   .\scripts\verify_branch2.ps1
#   .\scripts\verify_branch2.ps1 -SkipPytest
param([switch]$SkipPytest)
$ErrorActionPreference = "Stop"
Set-Location (Join-Path $PSScriptRoot "..")
if (-not (Test-Path ".venv\Scripts\python.exe")) { python -m venv .venv }
$py = ".venv\Scripts\python.exe"
& $py -m pip install -q -U pip
& $py -m pip install -q -e ".[dev]"
$extra = @()
if ($SkipPytest) { $extra += "--skip-pytest" }
& $py scripts\verify_branch2.py @extra
$rc = $LASTEXITCODE
Write-Host ""
Write-Host "Detailed output: reports\verify-branch2\report.txt"
Write-Host "Diff with:       git diff --no-index verification\branch2\expected\report.txt reports\verify-branch2\report.txt"
Write-Host "   or in PyCharm: select both files > right-click > Compare Files (Ctrl+D)"
exit $rc
