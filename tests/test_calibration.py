"""Confidence calibration: Wilson bound, band edges, small samples, adapters, YAML write-back."""

import json
import re
import shutil
from pathlib import Path

import pytest
import yaml

from abm import calibration as cal
from abm.cli import main
from abm.models import Level

T0 = "2026-10-01T12:00:00Z"


@pytest.fixture
def behaviors(behaviors):
    """Repo behaviors with confidence pinned to medium.

    Tests must not depend on the live `confidence:` values: those are exactly what
    `abm calibrate --write` changes, and a real calibration commit must not break CI.
    """
    return {k: b.model_copy(update={"confidence": Level.medium}) for k, b in behaviors.items()}


def _native(bid: str, tp: int = 0, fp: int = 0, bp: int = 0, start: int = 0) -> list[dict]:
    outcomes = ["true_positive"] * tp + ["false_positive"] * fp + ["benign_positive"] * bp
    return [{"behavior_id": bid, "alert_id": f"{bid}-{start + i}", "disposition": d,
             "closed_at": f"2026-10-{1 + (start + i) % 28:02d}T12:00:00Z"}
            for i, d in enumerate(outcomes)]


def _calibrate(rows, behaviors, **kw):
    parsed = cal.parse_records(rows)
    return cal.calibrate(parsed.records, list(behaviors.values()), skipped=parsed.skipped,
                         read=parsed.read, **kw)


def _row(rep, bid):
    return next(r for r in rep.rows if r.behavior_id == bid)


# ---------------------------------------------------------------- statistics
def test_wilson_lower_bound_known_values():
    assert cal.wilson_lower_bound(20, 20) == pytest.approx(0.8389, abs=1e-4)
    assert cal.wilson_lower_bound(15, 20) == pytest.approx(0.5313, abs=1e-4)
    assert cal.wilson_lower_bound(0, 20) == 0.0
    assert cal.wilson_lower_bound(0, 0) == 0.0
    # more evidence at the same rate tightens the bound upward
    assert cal.wilson_lower_bound(90, 100) > cal.wilson_lower_bound(18, 20)


@pytest.mark.parametrize(("lb", "level"), [
    (1.0, Level.critical), (0.95, Level.critical), (0.9499, Level.high),
    (0.80, Level.high), (0.7999, Level.medium),
    (0.50, Level.medium), (0.4999, Level.low), (0.0, Level.low),
])
def test_band_edges(lb, level):
    assert cal.band_for(lb) == level


@pytest.mark.parametrize(("tp", "n", "band"), [
    (14, 20, "low"), (15, 20, "medium"),        # low | medium edge (LB 0.481 | 0.531)
    (19, 20, "medium"), (20, 20, "high"),       # medium | high edge (LB 0.764 | 0.839)
    (72, 72, "high"), (73, 73, "critical"),     # high | critical edge (LB 0.9493 | 0.9500)
])
def test_synthetic_sets_land_on_each_side_of_a_band_edge(behaviors, tp, n, band):
    rep = _calibrate(_native("BHV-PI-001", tp=tp, fp=n - tp), behaviors)
    r = _row(rep, "BHV-PI-001")
    assert (r.n, r.tp, r.calibrated) == (n, tp, band)
    assert r.precision == pytest.approx(tp / n, abs=1e-4)


# ---------------------------------------------------------------- small samples
def test_below_min_samples_reports_insufficient_data_not_a_number(behaviors):
    rep = _calibrate(_native("BHV-PI-001", tp=19), behaviors)
    r = _row(rep, "BHV-PI-001")
    assert r.n == 19 and r.verdict == "insufficient_data"
    assert r.precision is None and r.lower_bound is None and r.calibrated is None
    assert not r.noisy and rep.changes == [] and rep.insufficient == [r]


def test_exactly_min_samples_is_calibrated(behaviors):
    r = _row(_calibrate(_native("BHV-PI-001", tp=20), behaviors), "BHV-PI-001")
    assert r.n == 20 and r.calibrated == "high" and r.lower_bound is not None


def test_min_samples_is_configurable(behaviors):
    rows = _native("BHV-PI-001", tp=5)
    assert _row(_calibrate(rows, behaviors), "BHV-PI-001").calibrated is None
    assert _row(_calibrate(rows, behaviors, min_samples=5), "BHV-PI-001").calibrated is not None
    with pytest.raises(ValueError):
        _calibrate(rows, behaviors, min_samples=0)


def test_excluded_outcomes_do_not_count_toward_n(behaviors):
    rows = _native("BHV-PI-001", tp=15) + [
        {"behavior_id": "BHV-PI-001", "alert_id": f"u{i}", "disposition": "undetermined",
         "closed_at": T0} for i in range(10)]
    r = _row(_calibrate(rows, behaviors), "BHV-PI-001")
    assert (r.n, r.excluded, r.calibrated) == (15, 10, None)


# ---------------------------------------------------------------- benign positives
def test_benign_positive_counts_as_noise_by_default_or_can_be_excluded(behaviors):
    rows = _native("BHV-PI-001", tp=20, bp=10)
    noise = _row(_calibrate(rows, behaviors), "BHV-PI-001")
    assert noise.n == 30 and noise.calibrated == "low"   # 20/30, LB 0.488
    excl = _row(_calibrate(rows, behaviors, benign="exclude"), "BHV-PI-001")
    assert excl.n == 20 and excl.calibrated == "high"


# ---------------------------------------------------------------- verdicts and noisy behaviors
def test_verdict_relative_to_current_confidence(behaviors):
    rep = _calibrate(_native("BHV-EXF-003", tp=20) + _native("BHV-PI-001", tp=5, fp=15)
                     + _native("BHV-JB-001", tp=16, fp=4), behaviors)
    assert _row(rep, "BHV-EXF-003").verdict == "raise"
    assert _row(rep, "BHV-PI-001").verdict == "lower"
    jb = _row(rep, "BHV-JB-001")  # 16/20 -> LB 0.584 -> medium
    assert jb.calibrated == "medium"
    assert jb.verdict == {"low": "raise", "medium": "unchanged", "high": "lower"}[jb.current]


def test_noisy_behavior_listed_with_false_positive_notes(behaviors):
    rows = _native("BHV-EXF-003", tp=5, fp=15) + _native("BHV-PI-001", tp=18, fp=2)
    rows[5]["reason"] = "batch eval job"
    rep = _calibrate(rows, behaviors)
    assert [r.behavior_id for r in rep.noisy] == ["BHV-EXF-003"]
    exf = _row(rep, "BHV-EXF-003")
    assert exf.noise_rate == 0.75
    assert exf.false_positive_notes == behaviors["BHV-EXF-003"].detection.false_positives
    assert exf.fp_reasons == {"batch eval job": 1}
    md = cal.markdown_report(rep)
    tuning = md.split("## Tuning candidates")[1]
    assert "BHV-EXF-003" in tuning and "BHV-PI-001" not in tuning
    for note in exf.false_positive_notes:
        assert note in tuning


def test_insufficient_data_is_never_flagged_noisy(behaviors):
    rep = _calibrate(_native("BHV-EXF-003", fp=19), behaviors)
    assert rep.noisy == []


# ---------------------------------------------------------------- input handling
def test_dedupe_keeps_latest_disposition_per_alert(behaviors):
    rows = _native("BHV-PI-001", tp=20)
    rows.append({**rows[0], "disposition": "false_positive", "closed_at": "2026-11-30T00:00:00Z"})
    rep = _calibrate(rows, behaviors)
    r = _row(rep, "BHV-PI-001")
    assert (r.n, r.tp, r.fp) == (20, 19, 1)
    assert any("superseded" in k for k in rep.skipped)


def test_since_filters_by_closed_at(behaviors):
    old = [{**d, "closed_at": "2025-01-01T00:00:00Z"} for d in _native("BHV-PI-001", fp=30, start=100)]
    rep = _calibrate(_native("BHV-PI-001", tp=20) + old, behaviors,
                     since=cal.parse_since("2026-06-01"))
    assert _row(rep, "BHV-PI-001").fp == 0
    assert cal.parse_since("90d", now=cal.parse_time(T0)).isoformat().startswith("2026-07-03")
    with pytest.raises(cal.DispositionError):
        cal.parse_since("last quarter")


def test_unknown_behavior_ids_reported_not_calibrated(behaviors):
    rep = _calibrate(_native("BHV-PI-999", tp=30), behaviors)
    assert rep.rows == [] and rep.unknown == {"BHV-PI-999": 30}


def test_xsoar_adapter(behaviors):
    rows = [
        {"id": "101", "name": "[BHV-PI-001] Instruction-override pattern", "closeReason": "False Positive",
         "closed": T0, "status": 2},
        {"id": "102", "name": "x", "closeReason": "Resolved", "closed": T0,
         "CustomFields": {"abmbehaviorid": "BHV-PI-001"}},
        {"id": "103", "name": "y", "closeReason": "Resolved - Security Testing", "closed": T0,
         "labels": [{"type": "behavior_id", "value": "BHV-PI-001"}]},
        {"id": "104", "name": "[BHV-PI-001] z", "closeReason": "Duplicate", "closed": T0},
        {"id": "105", "name": "[BHV-PI-001] open", "closeReason": "", "closed": "0001-01-01T00:00:00Z"},
        {"id": "106", "name": "[BHV-PI-001] w", "closeReason": "Closed by automation", "closed": T0},
    ]
    res = cal.parse_records(rows)
    assert [(d.alert_id, d.outcome, d.source) for d in res.records] == [
        ("101", "fp", "xsoar"), ("102", "tp", "xsoar"), ("103", "bp", "xsoar"), ("104", "exclude", "xsoar")]
    assert res.records[0].closed_at == cal.parse_time(T0)
    assert res.skipped["xsoar: not closed / unclassified"] == 1
    assert any("unmapped label 'Closed by automation'" in k for k in res.skipped)
    # --map overrides the built-in table (and fills gaps)
    res2 = cal.parse_records(rows, overrides=cal.parse_overrides(["Resolved=exclude", "Closed by automation=tp"]))
    assert {d.alert_id: d.outcome for d in res2.records}["102"] == "exclude"
    assert {d.alert_id: d.outcome for d in res2.records}["106"] == "tp"


def test_sentinel_rest_json_and_portal_csv(tmp_path):
    rest = {"value": [
        {"name": "guid-1", "properties": {
            "title": "BHV-EXF-003 High-volume systematic inference queries", "incidentNumber": 41,
            "status": "Closed", "classification": "BenignPositive",
            "classificationReason": "SuspiciousButExpected", "lastModifiedTimeUtc": "2026-10-01T12:00:00.1234567Z"}},
        {"name": "guid-2", "properties": {"title": "BHV-EXF-003 ...", "incidentNumber": 42,
                                          "status": "Active", "classification": ""}},
    ]}
    (tmp_path / "sentinel.json").write_text(json.dumps(rest), encoding="utf-8")
    res = cal.load_dispositions([tmp_path / "sentinel.json"])
    [d] = res.records
    assert (d.behavior_id, d.alert_id, d.outcome, d.reason) == ("BHV-EXF-003", "41", "bp", "SuspiciousButExpected")
    assert d.closed_at is not None and d.closed_at.microsecond == 123456

    csv_text = ("\ufeffIncident number,Title,Status,Classification,Classification reason,Closed time\r\n"
                "7,BHV-PI-001 Instruction override,Closed,FalsePositive,IncorrectAlertLogic,2026-10-02T08:00:00Z\r\n"
                "8,BHV-PI-001 and BHV-JB-001 merged,Closed,TruePositive,SuspiciousActivity,2026-10-02T08:00:00Z\r\n"
                "9,BHV-PI-001 Instruction override,Closed,Undetermined,,2026-10-02T08:00:00Z\r\n")
    (tmp_path / "sentinel.csv").write_bytes(csv_text.encode("utf-8"))
    res = cal.load_dispositions([tmp_path / "sentinel.csv"])
    assert [(d.alert_id, d.outcome, d.reason) for d in res.records] == [
        ("7", "fp", "IncorrectAlertLogic"), ("9", "exclude", None)]
    assert res.skipped["sentinel: several behavior ids in title"] == 1


def test_native_jsonl_and_bad_input(tmp_path):
    p = tmp_path / "d.jsonl"
    p.write_text("\n".join(json.dumps(r) for r in _native("BHV-PI-001", tp=2)) + "\n", encoding="utf-8")
    assert len(cal.load_dispositions([p]).records) == 2
    bad = tmp_path / "d.json"
    bad.write_text("{not json", encoding="utf-8")
    with pytest.raises(cal.DispositionError):
        cal.load_dispositions([bad])
    with pytest.raises(cal.DispositionError):
        cal.load_dispositions([tmp_path / "missing.csv"])
    with pytest.raises(cal.DispositionError):
        cal.parse_overrides(["Resolved=maybe"])


def test_bad_close_times_do_not_abort_the_run():
    """Regression (found by fuzzing): out-of-range epoch values raised OverflowError and crashed the CLI."""
    for v in (float("nan"), float("inf"), 1e300, -10**22, True, "2026-13-01", "garbage"):
        assert cal.parse_time(v) is None
    assert cal.parse_time(1790000000) == cal.parse_time(1790000000000)  # seconds and XSOAR milliseconds
    [d] = cal.parse_records([{"behavior_id": "BHV-PI-001", "alert_id": "1", "disposition": "tp",
                              "closed_at": 1e300}]).records
    assert d.closed_at is None


def test_zero_true_positives_gives_exactly_zero():
    """Regression (found by fuzzing): 0/3781 gave 2.7e-20 instead of 0."""
    assert all(cal.wilson_lower_bound(0, n) == 0.0 for n in range(1, 5000, 7))


def test_excel_exports_semicolon_utf16_and_non_utf8(tmp_path):
    rows = ["behavior_id;alert_id;disposition;closed_at", "BHV-PI-001;a1;false_positive;2026-10-01"]
    (tmp_path / "semi.csv").write_text("\r\n".join(rows), encoding="utf-8-sig")
    [d] = cal.load_dispositions([tmp_path / "semi.csv"]).records
    assert (d.behavior_id, d.outcome) == ("BHV-PI-001", "fp")
    tab = "\r\n".join(r.replace(";", "\t") for r in rows)
    (tmp_path / "unicode.txt").write_bytes(tab.encode("utf-16"))          # Excel "Unicode Text"
    assert len(cal.load_dispositions([tmp_path / "unicode.txt"]).records) == 1
    (tmp_path / "ansi.csv").write_bytes("behavior_id,alert_id,disposition,closed_at,note\r\n"
                                        "BHV-PI-001,a1,fp,2026-10-01,caf\xe9\r\n".encode("cp1252"))
    with pytest.raises(cal.DispositionError, match="CSV UTF-8"):
        cal.load_dispositions([tmp_path / "ansi.csv"])


# ---------------------------------------------------------------- YAML write-back
def test_set_confidence_is_a_single_line_edit():
    text = ("id: BHV-PI-001\r\nstatus: stable\r\nseverity: high\r\n"
            "confidence: medium      # tuned 2026-09\r\ndescription: >\r\n  confidence: low\r\n")
    new = cal.set_confidence(text, "high")
    assert new.splitlines(keepends=True)[3] == "confidence: high        # tuned 2026-09\r\n"
    old_lines, new_lines = text.splitlines(keepends=True), new.splitlines(keepends=True)
    assert [i for i, (a, b) in enumerate(zip(old_lines, new_lines, strict=True)) if a != b] == [3]
    assert cal.set_confidence('confidence: "low"\n', "medium") == 'confidence: "medium"\n'
    with pytest.raises(cal.WriteError):
        cal.set_confidence("id: x\n", "high")
    with pytest.raises(cal.WriteError):
        cal.set_confidence("confidence: low\nconfidence: high\n", "high")


@pytest.fixture
def project(tmp_path, root):
    """A throwaway project root with two real (CRLF, commented) behavior files."""
    for rel in ("behaviors/exfiltration/BHV-EXF-003.yaml", "behaviors/prompt-injection/BHV-PI-001.yaml"):
        (tmp_path / rel).parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(root / rel, tmp_path / rel)
        # pin the starting confidence so the tests survive a real `calibrate --write` commit
        f = tmp_path / rel
        f.write_bytes(re.sub(rb"(?m)^confidence: *\w+", b"confidence: medium", f.read_bytes()))
    return tmp_path


def _write_dispositions(path: Path, rows: list[dict]) -> Path:
    path.write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")
    return path


def test_cli_reports_without_write_leave_yaml_untouched(project, capsys):
    exf = project / "behaviors/exfiltration/BHV-EXF-003.yaml"
    before = exf.read_bytes()
    disp = _write_dispositions(project / "d.jsonl", _native("BHV-EXF-003", tp=20) + _native("BHV-PI-001", tp=3))
    rc = main(["--root", str(project), "calibrate", "--dispositions", str(disp)])
    assert rc == 0 and exf.read_bytes() == before
    data = json.loads((project / "reports/calibration.json").read_text(encoding="utf-8"))
    by_id = {b["behavior_id"]: b for b in data["behaviors"]}
    assert by_id["BHV-EXF-003"]["calibrated"] == "high" and by_id["BHV-EXF-003"]["verdict"] == "raise"
    assert by_id["BHV-PI-001"]["verdict"] == "insufficient_data" and by_id["BHV-PI-001"]["precision"] is None
    assert data["method"]["min_samples"] == 20
    md = (project / "reports/calibration.md").read_text(encoding="utf-8")
    assert "insufficient data" in md.lower() and "| BHV-PI-001 | 3 |" in md
    assert "insufficient data" in capsys.readouterr().out


def test_cli_write_changes_only_the_confidence_line(project, capsys):
    exf = project / "behaviors/exfiltration/BHV-EXF-003.yaml"
    pi = project / "behaviors/prompt-injection/BHV-PI-001.yaml"
    exf_before, pi_before = exf.read_bytes(), pi.read_bytes()
    status_before = yaml.safe_load(exf_before)["status"]
    disp = _write_dispositions(project / "d.jsonl",
                               _native("BHV-EXF-003", tp=20) + _native("BHV-PI-001", tp=1, fp=5))
    rc = main(["--root", str(project), "calibrate", "--dispositions", str(disp), "--write"])
    assert rc == 0
    after = exf.read_bytes()
    eol = b"\r\n" if b"\r\n" in exf_before else b"\n"  # works for CRLF and LF checkouts
    old_lines, new_lines = exf_before.splitlines(keepends=True), after.splitlines(keepends=True)
    changed = [(a, b) for a, b in zip(old_lines, new_lines, strict=True) if a != b]
    # every other line, including all ATLAS comments, is byte-identical
    assert changed == [(b"confidence: medium" + eol, b"confidence: high" + eol)]
    assert b"#" in exf_before and after.count(b"\r\n") == exf_before.count(b"\r\n")
    doc = yaml.safe_load(after)
    assert doc["status"] == status_before and doc["confidence"] == "high"
    assert pi.read_bytes() == pi_before  # insufficient data -> untouched
    assert "updated BHV-EXF-003: confidence medium -> high" in capsys.readouterr().out


def test_write_never_changes_status_even_when_lowering(project):
    exf = project / "behaviors/exfiltration/BHV-EXF-003.yaml"
    status_before = yaml.safe_load(exf.read_bytes())["status"]
    disp = _write_dispositions(project / "d.jsonl", _native("BHV-EXF-003", tp=2, fp=28))
    assert main(["--root", str(project), "calibrate", "--dispositions", str(disp), "--write"]) == 0
    doc = yaml.safe_load(exf.read_bytes())
    assert doc["confidence"] == "low" and doc["status"] == status_before


def test_cli_write_refuses_ambiguous_file_and_exits_1(project, capsys):
    exf = project / "behaviors/exfiltration/BHV-EXF-003.yaml"
    # PyYAML accepts duplicate keys (last wins), so the behavior loads; the writer must refuse.
    exf.write_bytes(re.sub(rb"(?m)^confidence: medium(\r?\n)", rb"confidence: high\1confidence: medium\1",
                           exf.read_bytes()))
    before = exf.read_bytes()
    disp = _write_dispositions(project / "d.jsonl", _native("BHV-EXF-003", tp=20, fp=0) +
                               _native("BHV-EXF-003", tp=0, fp=20, start=50))
    rc = main(["--root", str(project), "calibrate", "--dispositions", str(disp), "--write"])
    assert rc == 1 and exf.read_bytes() == before
    assert "BHV-EXF-003: not updated: expected exactly one" in capsys.readouterr().err


def test_write_verification_rejects_any_other_change(project, monkeypatch):
    """Defence in depth: if the line edit ever touched status (or anything else), nothing is written."""
    exf = project / "behaviors/exfiltration/BHV-EXF-003.yaml"
    before = exf.read_bytes()
    real = cal.set_confidence
    monkeypatch.setattr(cal, "set_confidence",
                        lambda text, level: real(text, level).replace("status: stable", "status: test"))
    with pytest.raises(cal.WriteError):
        cal.write_confidence(exf, "high")
    assert exf.read_bytes() == before
    assert not list(exf.parent.glob("*.tmp"))


# ---------------------------------------------------------------- security regressions (DAST findings)
def test_deeply_nested_json_is_a_clean_error(tmp_path):
    """CWE-674: 200k nested arrays raised RecursionError and a traceback."""
    p = tmp_path / "deep.json"
    p.write_text("[" * 200000 + "]" * 200000, encoding="utf-8")
    with pytest.raises(cal.DispositionError, match="nested too deeply"):
        cal.load_dispositions([p])


def test_untrusted_text_cannot_inject_markup_or_terminal_escapes(behaviors, tmp_path, capsys):
    """CWE-116 / CWE-79 / CWE-150: disposition content reached calibration.md and stderr verbatim."""
    evil = ["BHV-PI-001\x1b[2J\x1b]0;pwned\x07", "<img src=x onerror=alert(1)>", "![t](https://attacker.example/p.png)"]
    rows = [{"behavior_id": e, "alert_id": f"a{i}", "disposition": "tp", "closed_at": T0} for i, e in enumerate(evil)]
    rows += [{"behavior_id": "BHV-PI-001", "alert_id": "z", "disposition": "<script>alert(1)</script>", "closed_at": T0},
             {"behavior_id": "BHV-PI-001", "alert_id": "r", "disposition": "fp", "closed_at": T0,
              "reason": "[click](javascript:alert(1)) `code` <b>x</b>"}]
    parsed = cal.parse_records(rows)
    assert parsed.skipped["native: malformed behavior id"] == 3
    md = cal.markdown_report(cal.calibrate(parsed.records, list(behaviors.values()), min_samples=1,
                                           noisy_threshold=0.5, skipped=parsed.skipped))
    for bad in ("<img", "<script>", "\x1b", "<b>"):
        assert bad not in md
    # links / images / code spans need an unescaped ] or `; every one from the input must be escaped
    assert not re.search(r"(?<!\\)\]\((?:https?|javascript):", md)
    assert not re.search(r"(?<!\\)`code(?<!\\)`", md)
    assert "\\[click\\](javascript:" in md and "\\`code\\`" in md
    assert "&lt;script&gt;" in md                       # still visible to the reader, just inert
    p = tmp_path / "d.json"
    p.write_text(json.dumps(rows), encoding="utf-8")
    main(["--root", str(Path(__file__).resolve().parents[1]), "calibrate", "--dispositions", str(p),
          "--out", str(tmp_path / "r")])
    out = capsys.readouterr()
    assert "\x1b" not in out.out + out.err


def test_write_keeps_file_permissions(project):
    """CWE-732: the atomic write came from mkstemp (0600) and silently changed the file mode."""
    import os
    import stat
    exf = project / "behaviors/exfiltration/BHV-EXF-003.yaml"
    os.chmod(exf, 0o644)
    if stat.S_IMODE(exf.stat().st_mode) != 0o644:  # Windows: chmod only toggles read-only (0o666)
        pytest.skip("POSIX permission bits not supported on this platform")
    assert cal.write_confidence(exf, "high")
    assert stat.S_IMODE(exf.stat().st_mode) == 0o644


def test_write_refuses_symlinks(project, tmp_path_factory):
    """CWE-59: a symlinked behavior file was either followed (target edited) or replaced."""
    exf = project / "behaviors/exfiltration/BHV-EXF-003.yaml"
    target = tmp_path_factory.mktemp("elsewhere") / "target.yaml"
    target.write_bytes(exf.read_bytes())
    exf.unlink()
    try:
        exf.symlink_to(target)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks not permitted on this platform")
    before = target.read_bytes()
    with pytest.raises(cal.WriteError, match="symlink"):
        cal.write_confidence(exf, "high")
    assert target.read_bytes() == before and exf.is_symlink()


def test_long_custom_close_reasons_still_map():
    """Regression: display truncation (60 chars) must not affect --map / built-in label matching."""
    label = "Closed - confirmed malicious activity after investigation by tier 2 analyst team"
    rows = [{"behavior_id": "BHV-PI-001", "alert_id": "1", "disposition": label, "closed_at": T0}]
    res = cal.parse_records(rows, overrides=cal.parse_overrides([f"{label}=tp"]))
    assert [d.outcome for d in res.records] == ["tp"] and not res.skipped


def test_cli_bad_input_exits_2(project, capsys):
    rc = main(["--root", str(project), "calibrate", "--dispositions", str(project / "nope.csv")])
    assert rc == 2 and "calibrate:" in capsys.readouterr().err
