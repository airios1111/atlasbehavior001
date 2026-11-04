"""Confidence calibration from SOC alert dispositions.

Reads closed-alert dispositions (native export, Cortex XSOAR incidents or Microsoft Sentinel
incidents), computes per-behavior precision as a Wilson score lower bound, maps it to a confidence
`Level` band and optionally rewrites the `confidence:` line of each behavior YAML in place.

Precision = TP / (TP + FP [+ BP]). Benign positives (the detection fired correctly on activity that
turned out to be authorized, e.g. a red-team exercise) count as noise by default: they cost analyst
time exactly like a false positive, and they are what `detection.false_positives` documents.
Undetermined and duplicate closures are excluded from the sample.
"""

from __future__ import annotations

import csv
import io
import json
import math
import os
import re
import stat
import tempfile
from collections import Counter
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import yaml

from abm.models import BEHAVIOR_PREFIXES, Behavior, Level

TP, FP, BP, EXCLUDE = "tp", "fp", "bp", "exclude"
OUTCOMES = (TP, FP, BP, EXCLUDE)
SOURCES = ("native", "xsoar", "sentinel")

DEFAULT_MIN_SAMPLES = 20
DEFAULT_Z = 1.96  # 95% two-sided Wilson interval
DEFAULT_NOISY_THRESHOLD = 0.5

# Lower bound of precision -> confidence. Ordered high to low; first match wins.
BANDS: tuple[tuple[float, Level], ...] = (
    (0.95, Level.critical),
    (0.80, Level.high),
    (0.50, Level.medium),
    (0.0, Level.low),
)

BEHAVIOR_ID_SEARCH = re.compile(rf"\bBHV-(?:{'|'.join(BEHAVIOR_PREFIXES)})-\d{{3}}\b")
# Shape check for explicit behavior ids. Unknown-but-well-formed ids are reported; anything else is
# rejected without being echoed (dispositions are untrusted input: CWE-116 / CWE-150).
BEHAVIOR_ID_SHAPE = re.compile(r"^BHV-[A-Z0-9]{2,4}-\d{3}$")
_CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f\u2028\u2029\u202a-\u202e\u2066-\u2069]")


def _clean(v: Any, limit: int = 80) -> str:
    """Untrusted text -> single line without control / bidi characters, bounded length."""
    s = _CONTROL.sub(" ", str(v)).strip()
    return s if len(s) <= limit else s[: limit - 1] + "…"


def _norm(s: Any) -> str:
    """Normalize keys and labels: 'Close Reason', 'closeReason', 'close_reason' -> 'closereason'."""
    return re.sub(r"[^a-z0-9]", "", str(s).lower())


# Raw label (normalized) -> outcome, per source. Unknown labels are reported, never guessed.
NATIVE_LABELS = {
    "tp": TP, "truepositive": TP,
    "fp": FP, "falsepositive": FP,
    "bp": BP, "benignpositive": BP, "benigntruepositive": BP, "btp": BP,
    "undetermined": EXCLUDE, "duplicate": EXCLUDE,
}
# XSOAR 6 defaults are Resolved / False Positive / Duplicate / Other. "Resolved" is read as a true
# positive; if your SOC closes everything as Resolved, override it with --map Resolved=exclude.
# The "Resolved - ..." forms are the XSOAR 8 / XSIAM close reasons.
XSOAR_LABELS = {
    "resolved": TP, "truepositive": TP, "resolvedtruepositive": TP,
    "falsepositive": FP, "resolvedfalsepositive": FP,
    "benignpositive": BP, "benigntruepositive": BP, "securitytesting": BP,
    "resolvedsecuritytesting": BP, "knownissue": BP, "resolvedknownissue": BP,
    "duplicate": EXCLUDE, "duplicateincident": EXCLUDE, "resolvedduplicateincident": EXCLUDE,
    "other": EXCLUDE, "resolvedother": EXCLUDE, "resolvedauto": EXCLUDE,
}
SENTINEL_LABELS = {
    "truepositive": TP, "falsepositive": FP, "benignpositive": BP, "undetermined": EXCLUDE,
}
LABELS = {"native": NATIVE_LABELS, "xsoar": XSOAR_LABELS, "sentinel": SENTINEL_LABELS}

# Field aliases per source, compared after _norm().
BEHAVIOR_KEYS = ("behaviorid", "abmbehaviorid")
TEXT_KEYS = {  # searched for a BHV-... id when no explicit behavior field is present
    "native": ("title", "name"),
    "xsoar": ("name", "details"),
    "sentinel": ("title", "description"),
}
ALERT_KEYS = {
    "native": ("alertid", "id"),
    "xsoar": ("id", "incidentid", "alertid"),
    "sentinel": ("incidentnumber", "incidentname", "name", "incidentid", "alertid"),
}
CLOSED_KEYS = {
    "native": ("closedat", "closed", "closedtime"),
    "xsoar": ("closed", "closedat", "closetime"),
    "sentinel": ("closedtime", "closedtimeutc", "closedat", "lastmodifiedtimeutc",
                 "lastmodifiedtime"),
}
LABEL_KEY = {"native": "disposition", "xsoar": "closereason", "sentinel": "classification"}
# Short analyst reason kept for the tuning section (XSOAR close notes are free text, not kept).
REASON_KEY = {"native": "reason", "xsoar": "closenotes", "sentinel": "classificationreason"}


class DispositionError(ValueError):
    """Unreadable disposition input."""


class WriteError(ValueError):
    """A behavior YAML could not be updated safely."""


# ---------------------------------------------------------------- input
@dataclass
class Disposition:
    behavior_id: str
    alert_id: str
    outcome: str  # tp | fp | bp | exclude
    closed_at: datetime | None
    source: str
    label: str  # raw close reason / classification
    reason: str | None = None  # Sentinel classificationReason or native `reason` column


@dataclass
class ParseResult:
    records: list[Disposition] = field(default_factory=list)
    skipped: Counter = field(default_factory=Counter)  # reason -> count
    read: int = 0


def read_records(path: Path) -> list[dict[str, Any]]:
    """Rows from CSV, JSON (list, or {"data"|"value"|"incidents": [...]}) or JSONL."""
    try:
        raw = path.read_bytes()
    except OSError as e:
        raise DispositionError(f"{path}: {e.strerror or e}") from e
    text = _decode(raw, path)
    suffix = path.suffix.lower()
    stripped = text.lstrip()
    if suffix == ".csv" or (suffix not in (".json", ".jsonl", ".ndjson") and stripped[:1] not in "[{"):
        header = text.split("\n", 1)[0]
        delimiter = max((",", ";", "\t"), key=header.count)  # Excel uses ; or tab in some locales
        try:
            return [dict(r) for r in csv.DictReader(io.StringIO(text), delimiter=delimiter)]
        except csv.Error as e:
            raise DispositionError(f"{path}: invalid CSV: {e}") from e
    if suffix not in (".jsonl", ".ndjson"):
        try:
            return _unwrap(json.loads(text), path)
        except RecursionError as e:  # pathological nesting (CWE-674)
            raise DispositionError(f"{path}: JSON nested too deeply") from e
        except json.JSONDecodeError as e:
            if suffix == ".json":
                raise DispositionError(f"{path}: invalid JSON: {e}") from e
    rows = []
    for n, line in enumerate(text.splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            rows.append(json.loads(line))
        except RecursionError as e:
            raise DispositionError(f"{path}:{n}: JSON nested too deeply") from e
        except json.JSONDecodeError as e:
            raise DispositionError(f"{path}:{n}: invalid JSON: {e}") from e
    return rows


def _decode(raw: bytes, path: Path) -> str:
    """UTF-8 (with or without BOM) or BOM-marked UTF-16 (Excel "Unicode Text"); nothing is guessed."""
    try:
        if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
            return raw.decode("utf-16")
        return raw.decode("utf-8-sig")
    except UnicodeDecodeError as e:
        raise DispositionError(
            f"{path}: not UTF-8 or UTF-16 text (byte {e.start}); re-export or save as 'CSV UTF-8'") from e


def _unwrap(doc: Any, path: Path) -> list[dict[str, Any]]:
    if isinstance(doc, dict):
        for key in ("data", "value", "incidents", "dispositions"):  # XSOAR search / Sentinel REST
            if isinstance(doc.get(key), list):
                return doc[key]
        return [doc]
    if isinstance(doc, list):
        return doc
    raise DispositionError(f"{path}: expected a JSON list or object")


def _flatten(rec: dict[str, Any]) -> dict[str, Any]:
    """Normalize keys; lift Sentinel REST `properties` and XSOAR `CustomFields` to the top level."""
    out: dict[str, Any] = {}
    for k, v in rec.items():
        out.setdefault(_norm(k), v)
    for nested in ("properties", "customfields"):
        inner = out.get(nested)
        if isinstance(inner, dict):
            for k, v in inner.items():
                out.setdefault(_norm(k), v)
    return out


def _first(rec: dict[str, Any], keys: tuple[str, ...]) -> Any:
    for k in keys:
        v = rec.get(k)
        if v not in (None, "", []):
            return v
    return None


def detect_source(rec: dict[str, Any]) -> str | None:
    if "disposition" in rec:
        return "native"
    if "closereason" in rec:
        return "xsoar"
    if "classification" in rec:
        return "sentinel"
    return None


def parse_time(v: Any) -> datetime | None:
    if v in (None, ""):
        return None
    if isinstance(v, bool):
        return None
    if isinstance(v, (int, float)):  # epoch seconds, or milliseconds (XSOAR) above 1e11
        try:
            return datetime.fromtimestamp(v / 1000 if v > 1e11 else v, tz=UTC)
        except (OverflowError, ValueError, OSError):  # NaN, inf, out of range for the platform
            return None
    s = str(v).strip().replace("Z", "+00:00")
    s = re.sub(r"(\.\d{6})\d+", r"\1", s)  # .NET 7-digit fractions (Sentinel)
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    if dt.year <= 1:  # XSOAR uses 0001-01-01T00:00:00Z for "not closed"
        return None
    return dt


def parse_since(s: str, now: datetime | None = None) -> datetime:
    """'90d' (relative to now) or an ISO date/time."""
    m = re.fullmatch(r"(\d+)d", s.strip())
    if m:
        return (now or datetime.now(UTC)) - timedelta(days=int(m.group(1)))
    dt = parse_time(s)
    if dt is None:
        raise DispositionError(f"invalid --since '{s}' (expected e.g. 90d or 2026-01-01)")
    return dt


def parse_overrides(items: list[str] | None) -> dict[str, str]:
    """['Resolved=exclude', 'Closed - Tuned=fp'] -> {'resolved': 'exclude', 'closedtuned': 'fp'}."""
    out = {}
    for item in items or []:
        label, sep, outcome = item.rpartition("=")
        outcome = outcome.strip().lower()
        if not sep or not label.strip() or outcome not in OUTCOMES:
            raise DispositionError(f"invalid --map '{item}' (expected LABEL={'|'.join(OUTCOMES)})")
        out[_norm(label)] = outcome
    return out


def _behavior_id(rec: dict[str, Any], source: str) -> tuple[str | None, str | None]:
    """(behavior_id, problem). Explicit field first, then labels, then title/name text."""
    explicit = _first(rec, BEHAVIOR_KEYS)
    labels = rec.get("labels")
    if not explicit and isinstance(labels, list):  # XSOAR [{type, value}] / Sentinel [{labelName, labelType}]
        for lab in labels:
            if isinstance(lab, dict) and _norm(lab.get("type", "")) == "behaviorid" and lab.get("value"):
                explicit = lab["value"]
                break
    if explicit:
        bid = str(explicit).strip()
        return (bid, None) if BEHAVIOR_ID_SHAPE.match(bid) else (None, "malformed behavior id")
    haystack = " ".join(str(rec.get(k) or "") for k in TEXT_KEYS[source])
    if isinstance(labels, (list, str)):
        haystack += " " + json.dumps(labels)
    found = set(BEHAVIOR_ID_SEARCH.findall(haystack))
    if len(found) == 1:
        return found.pop(), None
    return None, ("several behavior ids in title" if found else "no behavior id")


def _is_open(rec: dict[str, Any], source: str) -> bool:
    status = rec.get("status")
    if source == "sentinel" and status not in (None, ""):
        return _norm(status) != "closed"
    return False


def parse_records(rows: list[dict[str, Any]], source: str = "auto",
                  overrides: dict[str, str] | None = None) -> ParseResult:
    """Convert raw rows to Dispositions. Problems are counted in `skipped`, never raised."""
    res = ParseResult(read=len(rows))
    overrides = overrides or {}
    for raw in rows:
        if not isinstance(raw, dict):
            res.skipped["not an object"] += 1
            continue
        rec = _flatten(raw)
        src = detect_source(rec) if source == "auto" else source
        if src is None:
            res.skipped["unrecognized record (no disposition / closeReason / classification)"] += 1
            continue
        raw_label = str(rec.get(LABEL_KEY[src]) or "").strip()
        label = _clean(raw_label, 60)  # display form only; mapping uses the full label
        if not label or _is_open(rec, src):
            res.skipped[f"{src}: not closed / unclassified"] += 1
            continue
        outcome = overrides.get(_norm(raw_label)) or LABELS[src].get(_norm(raw_label))
        if outcome is None:
            res.skipped[f"{src}: unmapped label '{label}' (use --map '{label}=tp|fp|bp|exclude')"] += 1
            continue
        bid, problem = _behavior_id(rec, src)
        if not bid:
            res.skipped[f"{src}: {problem}"] += 1
            continue
        alert_id = _first(rec, ALERT_KEYS[src])
        if alert_id is None:
            res.skipped[f"{src}: missing alert id"] += 1
            continue
        reason = rec.get(REASON_KEY[src])
        res.records.append(Disposition(
            behavior_id=bid, alert_id=_clean(alert_id, 200), outcome=outcome,
            closed_at=parse_time(_first(rec, CLOSED_KEYS[src])), source=src, label=label,
            reason=_clean(reason) if reason not in (None, "") and src != "xsoar" else None,
        ))
    return res


def load_dispositions(paths: list[Path], source: str = "auto",
                      overrides: dict[str, str] | None = None) -> ParseResult:
    total = ParseResult()
    for p in paths:
        r = parse_records(read_records(p), source, overrides)
        total.records += r.records
        total.skipped.update(r.skipped)
        total.read += r.read
    return total


def dedupe(records: list[Disposition]) -> tuple[list[Disposition], int]:
    """One disposition per (behavior, alert): the latest close wins (reopened + reclassified)."""
    best: dict[tuple[str, str], Disposition] = {}
    floor = datetime.min.replace(tzinfo=UTC)
    for r in records:
        key = (r.behavior_id, r.alert_id)
        cur = best.get(key)
        if cur is None or (r.closed_at or floor) >= (cur.closed_at or floor):
            best[key] = r
    return list(best.values()), len(records) - len(best)


# ---------------------------------------------------------------- statistics
def wilson_lower_bound(successes: int, n: int, z: float = DEFAULT_Z) -> float:
    """Lower bound of the Wilson score interval for a binomial proportion."""
    if n <= 0 or successes <= 0:
        return 0.0  # exact; the closed form leaves ~1e-20 of float noise here
    p = successes / n
    z2 = z * z
    centre = p + z2 / (2 * n)
    margin = z * math.sqrt(p * (1 - p) / n + z2 / (4 * n * n))
    return max(0.0, (centre - margin) / (1 + z2 / n))


def band_for(lower_bound: float) -> Level:
    for threshold, level in BANDS:
        if lower_bound >= threshold:
            return level
    return Level.low


# ---------------------------------------------------------------- calibration
@dataclass
class BehaviorCalibration:
    behavior_id: str
    name: str | None
    status: str | None
    current: str | None
    tp: int = 0
    fp: int = 0
    bp: int = 0
    excluded: int = 0
    n: int = 0
    precision: float | None = None
    lower_bound: float | None = None
    calibrated: str | None = None
    verdict: str = "insufficient_data"  # insufficient_data | unchanged | raise | lower
    noise_rate: float | None = None
    noisy: bool = False
    false_positive_notes: list[str] = field(default_factory=list)
    fp_reasons: dict[str, int] = field(default_factory=dict)
    first_closed: str | None = None
    last_closed: str | None = None
    source_path: str | None = None

    @property
    def sufficient(self) -> bool:
        return self.verdict != "insufficient_data"


@dataclass
class CalibrationReport:
    rows: list[BehaviorCalibration]
    unknown: dict[str, int]  # behavior ids in dispositions that are not in behaviors/
    skipped: dict[str, int]
    read: int
    counted: int
    min_samples: int
    z: float
    benign: str
    noisy_threshold: float
    since: str | None = None
    inputs: list[str] = field(default_factory=list)
    no_data: list[str] = field(default_factory=list)

    @property
    def calibrated(self) -> list[BehaviorCalibration]:
        return [r for r in self.rows if r.sufficient]

    @property
    def insufficient(self) -> list[BehaviorCalibration]:
        return [r for r in self.rows if not r.sufficient]

    @property
    def noisy(self) -> list[BehaviorCalibration]:
        return [r for r in self.rows if r.noisy]

    @property
    def changes(self) -> list[BehaviorCalibration]:
        return [r for r in self.rows if r.verdict in ("raise", "lower")]

    def to_dict(self) -> dict[str, Any]:
        return {
            "method": {
                "statistic": "wilson_lower_bound", "z": self.z, "min_samples": self.min_samples,
                "precision": "tp / (tp + fp + bp)" if self.benign == "noise" else "tp / (tp + fp)",
                "benign_positive": self.benign,
                "bands": [{"level": lvl.value, "min_lower_bound": t} for t, lvl in BANDS],
                "noisy_threshold": self.noisy_threshold,
            },
            "inputs": self.inputs, "since": self.since,
            "records_read": self.read, "records_counted": self.counted,
            "skipped": self.skipped, "unknown_behaviors": self.unknown,
            "behaviors": [asdict(r) for r in self.rows],
            "no_data": self.no_data,
        }


_ORDER = {lvl: i for i, lvl in enumerate(Level)}


def _relpath(p: Path, root: Path | None) -> str:
    """Repo-relative POSIX path for reports; absolute when outside root. Symlinks are not followed."""
    if root is not None:
        try:
            return p.absolute().relative_to(root.absolute()).as_posix()
        except ValueError:
            pass
    return str(p)


def calibrate(records: list[Disposition], behaviors: list[Behavior], *,
              min_samples: int = DEFAULT_MIN_SAMPLES, z: float = DEFAULT_Z,
              benign: str = "noise", noisy_threshold: float = DEFAULT_NOISY_THRESHOLD,
              since: datetime | None = None, skipped: Counter | None = None,
              read: int | None = None, root: Path | None = None) -> CalibrationReport:
    if min_samples < 1:
        raise ValueError("min_samples must be >= 1")
    if benign not in ("noise", "exclude"):
        raise ValueError("benign must be 'noise' or 'exclude'")
    skipped = Counter(skipped or {})
    records, dupes = dedupe(records)
    if dupes:
        skipped["superseded by a later disposition of the same alert"] += dupes
    if since is not None:
        kept = [r for r in records if r.closed_at is not None and r.closed_at >= since]
        if len(kept) != len(records):
            skipped[f"closed before --since {since.isoformat()} (or no close time)"] += len(records) - len(kept)
        records = kept

    by_id = {b.id: b for b in behaviors}
    grouped: dict[str, list[Disposition]] = {}
    unknown: Counter = Counter()
    for r in records:
        if r.behavior_id in by_id:
            grouped.setdefault(r.behavior_id, []).append(r)
        else:
            unknown[r.behavior_id] += 1

    rows = []
    counted = 0
    for bid in sorted(grouped):
        b, recs = by_id[bid], grouped[bid]
        c = Counter(r.outcome for r in recs)
        row = BehaviorCalibration(
            behavior_id=bid, name=b.name, status=b.status.value, current=b.confidence.value,
            tp=c[TP], fp=c[FP], bp=c[BP], excluded=c[EXCLUDE],
            false_positive_notes=list(b.detection.false_positives),
            fp_reasons=dict(Counter(r.reason for r in recs if r.outcome in (FP, BP) and r.reason)),
            source_path=_relpath(b.source_path, root) if b.source_path else None,
        )
        times = sorted(r.closed_at for r in recs if r.closed_at)
        if times:
            row.first_closed, row.last_closed = times[0].isoformat(), times[-1].isoformat()
        noise = row.fp + (row.bp if benign == "noise" else 0)
        row.n = row.tp + noise
        counted += row.n
        if row.n >= min_samples:
            row.precision = round(row.tp / row.n, 4)
            row.lower_bound = round(wilson_lower_bound(row.tp, row.n, z), 4)
            level = band_for(wilson_lower_bound(row.tp, row.n, z))  # band from the unrounded value
            row.calibrated = level.value
            cur = Level(row.current)
            row.verdict = ("unchanged" if level == cur
                           else "raise" if _ORDER[level] > _ORDER[cur] else "lower")
            row.noise_rate = round(noise / row.n, 4)
            row.noisy = noise / row.n >= noisy_threshold
        rows.append(row)

    return CalibrationReport(
        rows=rows, unknown=dict(sorted(unknown.items())), skipped=dict(skipped),
        read=read if read is not None else len(records), counted=counted,
        min_samples=min_samples, z=z, benign=benign, noisy_threshold=noisy_threshold,
        since=since.isoformat() if since else None,
        no_data=sorted(set(by_id) - set(grouped)),
    )


# ---------------------------------------------------------------- YAML write-back
_CONF_LINE = re.compile(r"^(confidence:[ \t]*)(['\"]?)([A-Za-z]+)\2([ \t]*)(#.*)?$")


def set_confidence(text: str, level: str) -> str:
    """Rewrite the single top-level `confidence:` line; every other byte is left untouched.

    A PyYAML round-trip would drop the ATLAS comments and reflow the file, so this is a line edit.
    Quoting, line ending and any trailing comment (and its column, where possible) are preserved.
    """
    lines = text.splitlines(keepends=True)
    hits = [i for i, line in enumerate(lines) if line.startswith("confidence:")]
    if len(hits) != 1:
        raise WriteError(f"expected exactly one top-level 'confidence:' line, found {len(hits)}")
    i = hits[0]
    body = lines[i].rstrip("\r\n")
    eol = lines[i][len(body):]
    m = _CONF_LINE.match(body)
    if not m:
        raise WriteError(f"unsupported confidence line: {body!r}")
    prefix, quote, old, gap, comment = m.groups()
    if comment:  # keep the comment column when the value length changes
        gap = " " * max(1, len(gap) + len(old) - len(level))
    lines[i] = f"{prefix}{quote}{level}{quote}{gap}{comment or ''}".rstrip() + eol
    return "".join(lines)


def write_confidence(path: Path, level: str) -> bool:
    """Update `path` in place. Returns False when the file already has `level`.

    Verifies the edited document parses to exactly the original with only `confidence` changed;
    in particular `status` can never change.
    """
    if path.is_symlink():  # never write through a link to somewhere else (CWE-59)
        raise WriteError("refusing to write through a symlink")
    raw = path.read_bytes()
    text = raw.decode("utf-8")
    new = set_confidence(text, level)
    if new == text:
        return False
    before, after = yaml.safe_load(text), yaml.safe_load(new)
    expected = {**before, "confidence": level}
    if after != expected or after.get("status") != before.get("status"):
        raise WriteError("edit would change more than the confidence value; file left untouched")
    mode = stat.S_IMODE(path.stat().st_mode)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(new.encode("utf-8"))
        os.chmod(tmp, mode)  # mkstemp creates 0600; keep the file's original permissions
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise
    return True


# ---------------------------------------------------------------- reports
def _pct(v: float | None) -> str:
    return "—" if v is None else f"{v * 100:.1f}%"


_MD_SPECIAL = re.compile(r"([\\`\[\]|])")  # no [..] -> no links or images; no ` -> no code spans


def _md_cell(s: Any) -> str:
    """Inert Markdown text: no HTML, links, images, code spans or table breaks (CWE-116)."""
    s = _clean(s, 500).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    return _MD_SPECIAL.sub(r"\\\1", s)


def markdown_report(rep: CalibrationReport) -> str:
    bands = " · ".join(
        f"{lvl.value} ≥ {t:.2f}" if t > 0 else f"{lvl.value} < {BANDS[-2][0]:.2f}" for t, lvl in BANDS
    )
    precision = "TP / (TP + FP + BP)" if rep.benign == "noise" else "TP / (TP + FP)"
    lines = [
        "# Confidence Calibration Report", "",
        f"Inputs: {', '.join(f'`{p}`' for p in rep.inputs) or '—'}  ",
        f"Records read: **{rep.read}**, counted toward precision: **{rep.counted}**, "
        f"excluded (undetermined / duplicate): **{sum(r.excluded for r in rep.rows)}**, "
        f"unknown behavior: **{sum(rep.unknown.values())}**, skipped: **{sum(rep.skipped.values())}**"
        + (f"  \nClosed on or after: `{rep.since}`" if rep.since else ""), "",
        f"Method: precision = {precision}; confidence comes from the Wilson score lower bound "
        f"(z = {rep.z}). Minimum sample: n ≥ {rep.min_samples}; smaller samples report "
        f"*insufficient data* and are never written.  ",
        f"Bands: {bands}", "",
        f"Behaviors with dispositions: **{len(rep.rows)}** "
        f"(calibrated {len(rep.calibrated)}, insufficient data {len(rep.insufficient)}); "
        f"confidence changes: **{len(rep.changes)}**; tuning candidates: **{len(rep.noisy)}**; "
        f"behaviors without any disposition: {len(rep.no_data)}", "",
    ]

    lines += ["## Calibrated", ""]
    if rep.calibrated:
        lines += ["| Behavior | Status | n | TP | FP | BP | Precision | Wilson LB | Current | Calibrated | Change |",
                  "|---|---|---|---|---|---|---|---|---|---|---|"]
        for r in rep.calibrated:
            change = {"raise": "▲ raise", "lower": "▼ lower"}.get(r.verdict, "=")
            lines.append(f"| {r.behavior_id} | {r.status} | {r.n} | {r.tp} | {r.fp} | {r.bp} | "
                         f"{_pct(r.precision)} | {_pct(r.lower_bound)} | {r.current} | "
                         f"**{r.calibrated}** | {change} |")
    else:
        lines.append(f"No behavior reached n ≥ {rep.min_samples}.")
    lines.append("")

    lines += [f"## Insufficient data (n < {rep.min_samples})", ""]
    if rep.insufficient:
        lines += ["| Behavior | n | TP | FP | BP | Current (kept) |", "|---|---|---|---|---|---|"]
        for r in rep.insufficient:
            lines.append(f"| {r.behavior_id} | {r.n} | {r.tp} | {r.fp} | {r.bp} | {r.current} |")
    else:
        lines.append("None.")
    lines.append("")

    noise_label = "FP + BP" if rep.benign == "noise" else "FP"
    lines += [f"## Tuning candidates ({noise_label} ≥ {rep.noisy_threshold:.0%} of closed alerts)", ""]
    if not rep.noisy:
        lines.append("None.")
    for r in sorted(rep.noisy, key=lambda r: -(r.noise_rate or 0)):
        lines += [f"### {r.behavior_id}: {_md_cell(r.name)}", "",
                  f"- Noise: **{_pct(r.noise_rate)}** of {r.n} (FP {r.fp}, BP {r.bp}, TP {r.tp}); "
                  f"confidence {r.current} → {r.calibrated}"]
        if r.fp_reasons:
            lines.append("- Analyst reasons: " + ", ".join(
                f"{_md_cell(k)} ×{v}" for k, v in sorted(r.fp_reasons.items(), key=lambda kv: -kv[1])))
        if r.false_positive_notes:
            lines.append("- Documented `detection.false_positives` (check whether the noise matches, "
                         "then allowlist it in `detection.filters`):")
            lines += [f"  - {_md_cell(n)}" for n in r.false_positive_notes]
        else:
            lines.append("- No `detection.false_positives` documented: record what analysts are closing.")
        if r.source_path:
            lines.append(f"- File: `{r.source_path}`")
        lines.append("")
    if not rep.noisy:
        lines.append("")

    if rep.unknown:
        lines += ["## Unknown behavior IDs", "",
                  "Dispositions reference behaviors that are not in `behaviors/` (renamed, deleted, or "
                  "another repository):", "", "| Behavior | Records |", "|---|---|"]
        lines += [f"| {_md_cell(k)} | {v} |" for k, v in rep.unknown.items()]
        lines.append("")
    if rep.skipped:
        lines += ["## Skipped records", "", "| Reason | Records |", "|---|---|"]
        lines += [f"| {_md_cell(k)} | {v} |" for k, v in sorted(rep.skipped.items(), key=lambda kv: -kv[1])]
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def write_reports(rep: CalibrationReport, out_dir: Path) -> list[Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    paths = {
        out_dir / "calibration.md": markdown_report(rep),
        out_dir / "calibration.json": json.dumps(rep.to_dict(), indent=2) + "\n",
    }
    for p, content in paths.items():
        p.write_text(content, encoding="utf-8")
    return list(paths)
