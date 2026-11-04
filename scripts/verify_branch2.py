"""Branch 2 (OCSF AI-event mapping) verification.

Runs every check for this branch and writes deterministic output files. You can diff them
line by line against the reference output committed in verification/branch2/expected/.

    python scripts/verify_branch2.py                 # run, write reports/verify-branch2/, compare
    python scripts/verify_branch2.py --no-compare    # run and write only
    python scripts/verify_branch2.py --out DIR       # choose the output directory
    python scripts/verify_branch2.py --write-expected  # maintainers: refresh the reference output

Output files (all compared except environment.txt):
    report.txt            step-by-step results: file hashes, extension check, mapping coverage,
                          per-fixture round trip, CLI runs, pytest per-test outcomes, ruff
    alerts.jsonl          alerts from every OCSF fixture (OCSF input) next to the native alerts
    findings.jsonl        OCSF Detection Findings for every OCSF fixture (with --respond dry-run)
    normalized.jsonl      every OCSF fixture event after normalize()
    mapping.tsv           source / class / field / OCSF path / tier
    environment.txt       Python, platform, packages, git commit (informational, not compared)

Nothing in the compared files depends on absolute paths, timings, dates or the Python version.
File hashes are taken over LF-normalized text, so a Windows CRLF checkout hashes the same.
"""

from __future__ import annotations

import argparse
import contextlib
import difflib
import hashlib
import io
import json
import os
import platform
import shutil
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from abm import __version__  # noqa: E402
from abm.cli import main as abm_main  # noqa: E402
from abm.engine import Engine, load_events  # noqa: E402
from abm.loader import load_behaviors  # noqa: E402
from abm.ocsf import (  # noqa: E402
    EXTENSION,
    OCSF_VERSION,
    SOURCES,
    detect_source,
    mapping_rows,
    normalize,
    read_ocsf,
    to_ocsf_event,
)
from abm.ocsf_schema import OcsfSchema  # noqa: E402

EXPECTED = ROOT / "verification" / "branch2" / "expected"
COMPARED = ["report.txt", "alerts.jsonl", "findings.jsonl", "normalized.jsonl", "mapping.tsv"]
BRANCH_FILES = [
    "src/abm/ocsf.py", "src/abm/ocsf_schema.py", "src/abm/cli.py",
    "tests/test_ocsf.py",
    "scripts/gen_ocsf_fixtures.py", "scripts/gen_ocsf_mapping_doc.py", "scripts/ocsf_vendor_base.py",
    "scripts/ocsf_check_upstream.py", "scripts/verify_branch2.py",
    "scripts/verify_branch2.ps1", "scripts/verify_branch2.sh",
    "docs/ocsf.md", "docs/ocsf-mapping.md", "docs/branches/branch2-ocsf-ai-event-mapping.md",
    "README.md", "Makefile", ".github/workflows/ci.yml", ".gitattributes",
]
BRANCH_DIRS = ["schemas/ocsf", "tests/fixtures/ocsf"]


class Report:
    def __init__(self) -> None:
        self.lines: list[str] = []
        self.failures: list[str] = []

    def h(self, title: str) -> None:
        self.lines += ["", "=" * 78, title, "=" * 78]

    def add(self, line: str = "") -> None:
        self.lines.append(line)

    def check(self, ok: bool, label: str) -> bool:
        self.add(f"[{'PASS' if ok else 'FAIL'}] {label}")
        if not ok:
            self.failures.append(label)
        return ok


def sha_text(p: Path) -> str:
    return hashlib.sha256(p.read_bytes().replace(b"\r\n", b"\n")).hexdigest()


def run_cli(argv: list[str]) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            rc = abm_main(["--root", str(ROOT), *argv])
        except SystemExit as e:  # argparse errors
            rc = int(e.code or 0)
    return rc, out.getvalue(), err.getvalue()


def rel(p: Path) -> str:
    return p.resolve().relative_to(ROOT).as_posix()


def strip_none(alerts: list[dict]) -> list[dict]:
    return [{**a, "context": {k: v for k, v in a["context"].items() if v is not None}} for a in alerts]


# ------------------------------------------------------------------------------------ steps
def step_inventory(r: Report) -> None:
    r.h("1. Branch file inventory (sha256 over LF-normalized content)")
    files = [ROOT / f for f in BRANCH_FILES]
    for d in BRANCH_DIRS:
        # Sort by POSIX string: WindowsPath ordering is case-insensitive, which reorders
        # README.md / MANIFEST.json relative to the Linux-generated reference report.
        files += sorted((p for p in (ROOT / d).rglob("*") if p.is_file()), key=lambda p: p.as_posix())
    for p in files:
        if p.is_file():
            r.add(f"{sha_text(p)}  {rel(p)}")
        else:
            r.check(False, f"missing file {p.relative_to(ROOT).as_posix()}")


def step_schema(r: Report, schema: OcsfSchema) -> None:
    r.h("2. OCSF base + abm extension")
    r.add(f"OCSF base version      : {schema.version}")
    r.add(f"OCSF base export sha256: {schema.base_source.get('sha256')}")
    r.add(f"abm extension          : {schema.extension.get('name')} uid={schema.extension.get('uid')} "
          f"version={schema.extension.get('version')}")
    r.add(f"core ai_operation profile present: {'ai_operation' in schema.profiles}")
    r.add(f"core ai_model attributes         : {sorted(a for a, v in schema.objects['ai_model'].attributes.items() if v.source == 'core')}")
    r.add(f"core message_context attributes  : {sorted(a for a, v in schema.objects['message_context'].attributes.items() if v.source == 'core')}")
    r.add(f"extension dictionary attributes  : {len(schema.ext_dictionary)}")
    r.add(f"extension new objects            : {sorted(schema.ext_objects)}")
    r.add(f"extension patches                : {sorted(f'{k}:{t}' for k, t in schema.patches)}")
    errs = schema.check_extension()
    for e in errs:
        r.add(f"    {e}")
    r.check(not errs, "extension self-check (no redefined core names, all references resolve)")
    r.check(schema.version == OCSF_VERSION, f"vendored base matches OCSF_VERSION {OCSF_VERSION}")


def step_mapping(r: Report, schema: OcsfSchema, out: Path, behaviors) -> None:
    r.h("3. Inbound mapping tables (all 12 KQL_TABLES sources)")
    from abm.compilers.common import KQL_TABLES

    r.check(set(SOURCES) == set(KQL_TABLES), f"SOURCES == KQL_TABLES ({len(SOURCES)} sources)")
    rows = mapping_rows(schema)
    with open(out / "mapping.tsv", "w", encoding="utf-8", newline="\n") as fh:
        fh.write("source\tclass_uid\tclass\tfield\tpath\ttier\n")
        for x in rows:
            fh.write(f"{x['source']}\t{x['class_uid']}\t{x['class']}\t{x['field']}\t{x['path']}\t{x['tier']}\n")
    r.add(f"{'source':18} {'class':28} {'fields':>6} {'core':>5} {'abm':>5} {'unmap':>5} {'alias':>5}")
    tot = {"core": 0, "abm": 0, "unmapped": 0, "alias": 0}
    for name, spec in SOURCES.items():
        mine = [x for x in rows if x["source"] == name and x["class_uid"] == spec.class_uid]
        c = {t: sum(1 for x in mine if x["tier"] == t) for t in tot}
        for t in tot:
            tot[t] += c[t]
        classes = "/".join(str(u) for u in spec.classes())
        r.add(f"{name:18} {classes:28} {len(mine):>6} {c['core']:>5} {c['abm']:>5} "
              f"{c['unmapped']:>5} {c['alias']:>5}")
    r.add(f"{'TOTAL':18} {'':28} {sum(tot.values()):>6} {tot['core']:>5} {tot['abm']:>5} "
          f"{tot['unmapped']:>5} {tot['alias']:>5}")
    bad = []
    for name, spec in SOURCES.items():
        for cuid in spec.classes():
            from abm.ocsf import CLASSES, Flag

            for fld, fs in spec.fields_for(cuid).items():
                try:
                    schema.resolve(CLASSES[cuid][0], fs.path if isinstance(fs, Flag) else fs)
                except KeyError as e:
                    bad.append(f"{name}/{cuid}/{fld}: {e}")
    for b in bad:
        r.add(f"    {b}")
    r.check(not bad, "every mapping path resolves in OCSF 1.8.0 + abm extension")
    missing = sorted({(ts.source, f) for b in behaviors for ts in [*b.telemetry.required, *b.telemetry.optional]
                      for f in ts.fields if f != "timestamp" and f not in SOURCES[ts.source].fields
                      and f not in SOURCES[ts.source].aliases})
    for m in missing:
        r.add(f"    unmapped declared field: {m}")
    r.check(not missing, "every field declared in behavior telemetry has an OCSF path")


def step_fixtures(r: Report, schema: OcsfSchema, out: Path, behaviors) -> None:
    r.h("4. OCSF fixtures: validity, normalization, same alerts as native JSONL")
    manifest = json.loads((ROOT / "tests/fixtures/ocsf/MANIFEST.json").read_text(encoding="utf-8"))
    r.check({m["source"] for m in manifest.values()} == set(SOURCES), "one OCSF fixture per source")
    with open(out / "normalized.jsonl", "w", encoding="utf-8", newline="\n") as norm_fh, \
            open(out / "alerts.jsonl", "w", encoding="utf-8", newline="\n") as alerts_fh:
        for name in sorted(manifest):
            m = manifest[name]
            path = ROOT / "tests/fixtures/ocsf" / name
            raw = read_ocsf(path)
            errs = [e for ev in raw for e in schema.validate_event(ev)]
            detected = sorted({detect_source({**ev, "metadata": {k: v for k, v in ev["metadata"].items()
                                                                 if k != "log_name"}}) for ev in raw})
            events = [normalize(ev) for ev in raw]
            native = load_events(ROOT / m["native_fixture"])
            same_events = all({k: v for k, v in n.items() if v is not None} ==
                              {k: v for k, v in e.items() if k in n or k not in
                               (set(SOURCES[m["source"]].aliases) | set(SOURCES[m["source"]].aliases.values()))}
                              for n, e in zip(native, events, strict=True))
            a_native = strip_none([a.to_dict() for a in Engine(behaviors).run(native)])
            a_ocsf = strip_none([a.to_dict() for a in Engine(behaviors).run(events)])
            r.add(f"- {name}  source={m['source']} class={m['class_uid']} events={len(raw)} "
                  f"native={m['native_fixture']}")
            for e in errs:
                r.add(f"    {e}")
            r.check(not errs, f"{name}: valid OCSF {OCSF_VERSION} + abm")
            r.check(detected == [m["source"]], f"{name}: source detected without log_name -> {detected}")
            r.check(same_events, f"{name}: normalize() == native events")
            r.check(a_ocsf == a_native and m["behavior"] in {a["behavior_id"] for a in a_ocsf},
                    f"{name}: alerts {[a['behavior_id'] for a in a_ocsf]} == native "
                    f"{[a['behavior_id'] for a in a_native]} (expects {m['behavior']})")
            for ev in events:
                norm_fh.write(json.dumps({"fixture": name, "event": ev}, sort_keys=True) + "\n")
            for a, b in zip(a_native, a_ocsf, strict=False):
                alerts_fh.write(json.dumps({"fixture": name, "native": a, "ocsf": b}, sort_keys=True) + "\n")


def step_corpus(r: Report, behaviors) -> None:
    r.h("5. Full corpus round trip: native -> OCSF -> normalized, every behavior fixture")
    n = events = 0
    fails = []
    for b in behaviors:
        for tc in b.tests:
            native = load_events(ROOT / tc.fixture)
            back = [normalize(to_ocsf_event(e, b.log_source)) for e in native]
            a1 = strip_none([a.to_dict() for a in Engine([b]).evaluate(b, native)])
            a2 = strip_none([a.to_dict() for a in Engine([b]).evaluate(b, back)])
            n += 1
            events += len(native)
            if a1 != a2 or (len(a2) > 0) != (tc.expect == "alert"):
                fails.append(f"{b.id} {tc.fixture}")
    for f in fails:
        r.add(f"    {f}")
    r.check(not fails, f"{len(behaviors)} behaviors, {n} fixtures, {events} events: identical alerts, "
                       f"test expectations hold")


def step_cli(r: Report, schema: OcsfSchema, out: Path) -> None:
    r.h("6. CLI (abm replay --input-format / --output-format ocsf)")
    local = Path(sys.executable).parent / ("abm.exe" if os.name == "nt" else "abm")
    exe = str(local) if local.is_file() else shutil.which("abm")
    if exe:
        p = subprocess.run([exe, "--version"], capture_output=True, text=True, check=False)  # noqa: S603
        r.check(p.returncode == 0 and p.stdout.strip() == f"abm {__version__}", "`abm` entry point installed")
    else:
        r.check(False, "`abm` entry point installed (run: python -m pip install -e \".[dev]\")")
    manifest = json.loads((ROOT / "tests/fixtures/ocsf/MANIFEST.json").read_text(encoding="utf-8"))
    with open(out / "findings.jsonl", "w", encoding="utf-8", newline="\n") as fh:
        for name in sorted(manifest):
            f = f"tests/fixtures/ocsf/{name}"
            nat = manifest[name]["native_fixture"]
            rc1, o1, _ = run_cli(["replay", "--fixture", nat])
            argv = ["replay", "--fixture", f, "--input-format", "ocsf", "--validate-ocsf", "--expect", "alert"]
            rc2, o2, e2 = run_cli(argv)
            same = strip_none([json.loads(x) for x in o1.splitlines()]) == [json.loads(x) for x in o2.splitlines()]
            r.add(f"$ abm {' '.join(argv)}")
            for line in e2.splitlines():
                r.add(f"    {line}")
            r.check(rc1 == 0 and rc2 == 0 and same, f"{name}: exit 0, stdout == native replay of {nat}")
            argv = ["replay", "--fixture", f, "--input-format", "ocsf", "--output-format", "ocsf",
                    "--validate-ocsf", "--respond"]
            rc3, o3, _ = run_cli(argv)
            findings = [json.loads(x) for x in o3.splitlines()]
            ok = rc3 == 0 and all(x["class_uid"] == 2004 and not schema.validate_event(x) for x in findings)
            r.check(ok, f"{name}: {len(findings)} Detection Finding(s), valid OCSF, "
                        f"ATLAS {[x['atlas_mapping']['technique']['uid'] for x in findings]}")
            for x in findings:
                fh.write(json.dumps({"fixture": name, "finding": x}, sort_keys=True) + "\n")
    rc, _, err = run_cli(["replay", "--fixture", "tests/fixtures/extraction_burst.jsonl",
                          "--output-format", "ocsf", "--validate-ocsf", "--expect", "alert"])
    r.add("$ abm replay --fixture tests/fixtures/extraction_burst.jsonl --output-format ocsf --validate-ocsf --expect alert")
    for line in err.splitlines():
        r.add(f"    {line}")
    r.check(rc == 0, "native input -> OCSF output")


def step_repo_checks(r: Report) -> None:
    r.h("7. Generated files are current")
    for script in ("gen_ocsf_fixtures.py", "gen_ocsf_mapping_doc.py"):
        p = subprocess.run([sys.executable, str(ROOT / "scripts" / script), "--check"],  # noqa: S603
                           capture_output=True, text=True, cwd=ROOT, check=False)
        r.add(f"$ python scripts/{script} --check")
        for line in p.stdout.splitlines():
            r.add(f"    {line}")
        r.check(p.returncode == 0, f"{script} --check")

    r.h("8. abm validate --run-tests / abm test")
    rc, o, _ = run_cli(["validate", "--run-tests", "-q"])
    r.add(f"    {o.strip().splitlines()[-1] if o.strip() else ''}")
    r.check(rc == 0, "abm validate --run-tests")
    rc, o, _ = run_cli(["test"])
    r.add(f"    {o.strip().splitlines()[-1] if o.strip() else ''}")
    r.check(rc == 0, "abm test")


def step_pytest(r: Report) -> None:
    r.h("9. pytest (per-test outcome, sorted)")
    with tempfile.TemporaryDirectory() as td:
        xml = Path(td) / "junit.xml"
        p = subprocess.run([sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider",  # noqa: S603
                            f"--junitxml={xml}", "-o", "junit_family=xunit1"],
                           capture_output=True, text=True, cwd=ROOT, check=False)
        if not xml.is_file():
            r.add(p.stdout[-2000:] + p.stderr[-2000:])
            r.check(False, "pytest ran")
            return
        rows, counts = [], {"passed": 0, "failed": 0, "error": 0, "skipped": 0}
        for tc in ET.parse(xml).getroot().iter("testcase"):  # noqa: S314 (file we just wrote)
            outcome = "passed"
            for tag in ("failure", "error", "skipped"):
                if tc.find(tag) is not None:
                    outcome = {"failure": "failed"}.get(tag, tag)
            counts[outcome] += 1
            mod = (tc.get("file") or tc.get("classname", "").replace(".", "/") + ".py").replace("\\", "/")
            rows.append(f"{outcome.upper():7} {mod}::{tc.get('name')}")
    for row in sorted(rows):
        r.add(row)
    r.add(f"summary: {counts['passed']} passed, {counts['failed']} failed, {counts['error']} errors, "
          f"{counts['skipped']} skipped")
    r.check(p.returncode == 0 and counts["failed"] == counts["error"] == 0, "pytest")


def step_ruff(r: Report) -> None:
    r.h("10. ruff check src tests")
    p = subprocess.run([sys.executable, "-m", "ruff", "check", "src", "tests", "--output-format", "concise"],
                       capture_output=True, text=True, cwd=ROOT, check=False)
    if "No module named ruff" in p.stderr:
        r.add("    ruff not installed (pip install -e \".[dev]\")")
        r.check(False, "ruff")
        return
    for line in (p.stdout or p.stderr).strip().splitlines():
        r.add(f"    {line}")
    r.check(p.returncode == 0, "ruff check src tests")


def environment(out: Path) -> None:
    lines = [f"generated: {datetime.now(tz=UTC).isoformat(timespec='seconds')}",
             f"python: {sys.version.split()[0]} ({platform.python_implementation()})",
             f"platform: {platform.platform()}", f"abm: {__version__}"]
    from importlib.metadata import PackageNotFoundError, version

    for pkg in ("pydantic", "PyYAML", "pytest", "ruff"):
        try:
            lines.append(f"{pkg}: {version(pkg)}")
        except PackageNotFoundError:
            lines.append(f"{pkg}: not installed")
    git = shutil.which("git")
    if git:
        for args in (["rev-parse", "--abbrev-ref", "HEAD"], ["rev-parse", "HEAD"], ["status", "--short"]):
            p = subprocess.run([git, *args], capture_output=True, text=True, cwd=ROOT, check=False)  # noqa: S603
            lines.append(f"git {' '.join(args)}: {p.stdout.strip() or p.stderr.strip()}")
    (out / "environment.txt").write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")


def compare(out: Path, expected: Path) -> int:
    print(f"\ncomparing {out} with {expected}")
    if not expected.is_dir():
        print("  no expected output found")
        return 1
    differ = 0
    for name in COMPARED:
        a, b = expected / name, out / name
        if not a.is_file() or not b.is_file():
            print(f"  {name}: missing ({'expected' if not a.is_file() else 'local'})")
            differ += 1
            continue
        la = a.read_text(encoding="utf-8").replace("\r\n", "\n").splitlines(keepends=True)
        lb = b.read_text(encoding="utf-8").replace("\r\n", "\n").splitlines(keepends=True)
        if la == lb:
            print(f"  {name}: identical")
            continue
        differ += 1
        diff = list(difflib.unified_diff(la, lb, f"expected/{name}", f"local/{name}", n=1))
        print(f"  {name}: {sum(1 for d in diff if d[:1] in '+-') - 2} changed line(s)")
        sys.stdout.writelines(diff[:80])
        if len(diff) > 80:
            print(f"  ... {len(diff) - 80} more diff lines; run a diff tool on the two files")
    print("RESULT: identical to the reference output" if not differ else
          f"RESULT: {differ} file(s) differ from the reference output")
    return 1 if differ else 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--out", default=str(ROOT / "reports" / "verify-branch2"))
    ap.add_argument("--no-compare", action="store_true")
    ap.add_argument("--expected", default=str(EXPECTED))
    ap.add_argument("--write-expected", action="store_true", help="copy the results to --expected")
    ap.add_argument("--skip-pytest", action="store_true", help="faster run without the pytest step")
    a = ap.parse_args()
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    os.chdir(ROOT)

    r = Report()
    r.add("ATLAS Behavior Map - branch2 verification: OCSF AI-event mapping")
    r.add(f"abm {__version__} | OCSF {OCSF_VERSION} | extension {EXTENSION['name']} {EXTENSION['version']}")
    schema = OcsfSchema.load(ROOT)
    res = load_behaviors(ROOT / "behaviors")
    r.check(not res.errors, f"{len(res.behaviors)} behaviors load without errors")
    step_inventory(r)
    step_schema(r, schema)
    step_mapping(r, schema, out, res.behaviors)
    step_fixtures(r, schema, out, res.behaviors)
    step_corpus(r, res.behaviors)
    step_cli(r, schema, out)
    step_repo_checks(r)
    if not a.skip_pytest:
        step_pytest(r)
    step_ruff(r)
    r.h("RESULT")
    r.add(f"checks failed: {len(r.failures)}")
    for f in r.failures:
        r.add(f"  - {f}")
    r.add("OVERALL: PASS" if not r.failures else "OVERALL: FAIL")
    (out / "report.txt").write_text("\n".join(r.lines) + "\n", encoding="utf-8", newline="\n")
    environment(out)
    print("\n".join(r.lines[-(len(r.failures) + 3):]))
    print(f"\nwrote {', '.join(COMPARED + ['environment.txt'])} -> {out}")

    if a.write_expected:
        exp = Path(a.expected)
        exp.mkdir(parents=True, exist_ok=True)
        for name in COMPARED:
            shutil.copyfile(out / name, exp / name)
        print(f"reference output refreshed -> {exp}")
        return 0 if not r.failures else 1
    rc = 0 if not r.failures else 1
    if not a.no_compare:
        rc = max(rc, compare(out, Path(a.expected)))
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
