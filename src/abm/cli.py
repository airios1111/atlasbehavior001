"""abm command-line interface."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from abm import __version__
from abm.catalog import AtlasCatalog, sync
from abm.compilers import TARGETS, render
from abm.compilers.common import KQL_PROFILES
from abm.coverage import SCORE_LABEL, compute, gaps, write_reports
from abm.engine import Engine, load_events, run_tests
from abm.loader import find_root, load_behaviors
from abm.ocsf import SOURCES as OCSF_SOURCES
from abm.ocsf import OcsfMappingError, normalize, read_ocsf, to_detection_finding
from abm.response import DryRunExecutor, WebhookExecutor, XsoarExecutor, plan, run_plan
from abm.validator import validate


# ---------------------------------------------------------------- helpers
def _ctx(args):
    root = Path(args.root).resolve() if args.root else find_root()
    catalog_path = Path(args.catalog) if args.catalog else root / "atlas" / "catalog.yaml"
    catalog = AtlasCatalog.load(catalog_path)
    return root, catalog


def _behaviors(root: Path, path: str | None):
    res = load_behaviors(Path(path) if path else root / "behaviors")
    for e in res.errors:
        print(f"[ERROR  ] {e.path}: {e.message}", file=sys.stderr)
    return res


def _table(rows: list[list[str]], headers: list[str]) -> str:
    widths = [max(len(str(x)) for x in col) for col in zip(headers, *rows, strict=True)]
    fmt = "  ".join(f"{{:<{w}}}" for w in widths)
    out = [fmt.format(*headers), fmt.format(*["-" * w for w in widths])]
    out += [fmt.format(*[str(c) for c in r]) for r in rows]
    return "\n".join(out)


# ---------------------------------------------------------------- commands
def cmd_validate(args) -> int:
    root, catalog = _ctx(args)
    res = load_behaviors(Path(args.path) if args.path else root / "behaviors")
    findings = validate(res, catalog, root)
    errors = [f for f in findings if f.level == "error"]
    for f in findings:
        if f.level == "error" or not args.quiet:
            print(f)
    if args.run_tests:
        for b in res.behaviors:
            for fixture, expect, ok, n in run_tests(b, root):
                if not ok:
                    errors.append(None)  # type: ignore[arg-type]
                    print(f"[ERROR  ] {b.id}: test {fixture} expected {expect}, got {n} alert(s)")
    if catalog.source == "seed":
        print("[WARNING] catalog is the unverified seed subset; run `abm atlas-sync` for drift checks "
              "against the official ATLAS release")
    print(f"\n{len(res.behaviors)} behavior(s), {len(errors)} error(s), "
          f"{len(findings) - len([f for f in findings if f.level == 'error'])} warning(s)")
    return 1 if errors else 0


def cmd_compile(args) -> int:
    root, _ = _ctx(args)
    res = _behaviors(root, args.path)
    targets = list(TARGETS) if args.target == "all" else [args.target]
    out_root = Path(args.out) if args.out else root / "dist"
    n = 0
    for t in targets:
        _, ext = TARGETS[t]
        out = out_root / t if (args.target == "all" or not args.out) else out_root
        out.mkdir(parents=True, exist_ok=True)
        for b in res.behaviors:
            if b.status.value == "deprecated" and not args.include_deprecated:
                continue
            (out / f"{b.id}{ext}").write_text(render(t, b, args.profile), encoding="utf-8")
            n += 1
    print(f"compiled {n} rule(s) -> {out_root}")
    return 1 if res.errors else 0


def cmd_sentinel_build(args) -> int:
    from abm import sentinel_solution as sol

    root, catalog = _ctx(args)
    res = _behaviors(root, None)
    if res.errors:
        return 1
    out = Path(args.out) if args.out else root / "integrations" / "sentinel"
    layer = json.loads(Path(args.layer).read_text(encoding="utf-8")) if args.layer else None
    files = sol.build(res.behaviors, catalog, root, layer)
    if args.check:
        problems = sol.check(files, out)
        for p in problems:
            print(p)
        print(f"{len(files)} file(s) expected, {len(problems)} difference(s) in {out}"
              + ("" if not problems else ". Run `abm sentinel-build` and commit the result."))
        return 1 if problems else 0
    changed = sol.write(files, out)
    print(f"sentinel solution: {len(files)} file(s), {len(changed)} changed -> {out}")
    return 0


def cmd_sentinel_validate(args) -> int:
    from abm import sentinel_solution as sol

    root = Path(args.root).resolve() if args.root else find_root()
    out = Path(args.path) if args.path else root / "integrations" / "sentinel"
    problems = sol.validate_dir(out)
    for p in problems:
        print(p)
    n = len(list((out / sol.RULES_DIR).glob("*.yaml"))) if (out / sol.RULES_DIR).is_dir() else 0
    print(f"{n} analytic rule(s), {len(problems)} error(s) in {out}")
    return 1 if problems else 0


def cmd_map(args) -> int:
    root, catalog = _ctx(args)
    res = _behaviors(root, None)
    bs = [b for b in res.behaviors if not args.behavior or b.id == args.behavior]
    if args.technique:
        bs = [b for b in bs if any(t.id.startswith(args.technique) for t in b.atlas.techniques)]
    if not bs:
        print("no matching behaviors", file=sys.stderr)
        return 1
    if args.format == "json":
        print(json.dumps([{
            "behavior": b.id, "name": b.name, "status": b.status.value,
            "tactics": [{"id": t, "name": catalog.name(t)} for t in b.atlas.tactics],
            "techniques": [{"id": t.id, "name": catalog.name(t.id), "relationship": t.relationship}
                           for t in b.atlas.techniques],
            "mitigations": [{"id": m, "name": catalog.name(m)} for m in b.countermeasures.mitigations],
            "response": [s.action for s in b.countermeasures.response],
            "attack_bridge": b.attack_bridge,
        } for b in bs], indent=2))
        return 0
    rows = []
    for b in bs:
        for t in b.atlas.techniques:
            rows.append([b.id, b.status.value, t.id, t.relationship, catalog.name(t.id),
                         ", ".join(b.countermeasures.mitigations),
                         ", ".join(s.action for s in b.countermeasures.response)])
    print(_table(rows, ["BEHAVIOR", "STATUS", "TECHNIQUE", "REL", "NAME", "MITIGATIONS", "RESPONSE"]))
    return 0


def cmd_coverage(args) -> int:
    root, catalog = _ctx(args)
    res = _behaviors(root, None)
    cov = compute(res.behaviors, catalog, root)
    paths = write_reports(cov, catalog, Path(args.out) if args.out else root / "reports",
                          Path(args.layer) if args.layer else None)
    counts = {s: sum(1 for c in cov.values() if c.score == s) for s in SCORE_LABEL}
    print(_table([[s, SCORE_LABEL[s], counts[s]] for s in SCORE_LABEL], ["SCORE", "MEANING", "TECHNIQUES"]))
    for p in paths:
        print(f"wrote {p}")
    return 0


def cmd_gaps(args) -> int:
    root, catalog = _ctx(args)
    res = _behaviors(root, None)
    gs = gaps(compute(res.behaviors, catalog, root), args.tactic, args.below)
    rows = [[g.technique, g.name, ", ".join(g.tactics), g.score] for g in sorted(gs, key=lambda g: g.technique)]
    print(_table(rows, ["TECHNIQUE", "NAME", "TACTICS", "SCORE"]) if rows else "no gaps")
    return 0


def _executor(args):
    if args.xsoar:
        # secrets only from the environment, never the command line (shell history, process list)
        return XsoarExecutor(args.xsoar, os.environ.get("XSOAR_API_KEY", ""),
                             os.environ.get("XSOAR_API_KEY_ID") or None,
                             incident_type=args.xsoar_incident_type)
    if not args.respond:
        return None
    return WebhookExecutor(args.webhook) if args.webhook else DryRunExecutor()


def _ocsf_schema(root: Path):
    from abm.ocsf_schema import OcsfSchema  # only needed with --validate-ocsf

    try:
        return OcsfSchema.load(root)
    except OSError as e:
        raise ValueError(f"cannot load OCSF schema files under {root}/schemas/ocsf: {e}") from e


def _load_replay_events(args, schema) -> tuple[list[dict], int]:
    """Returns (normalized events, number of OCSF validation errors in the input)."""
    path = Path(args.fixture)
    if args.input_format == "native":
        return load_events(path), 0
    try:
        raw = read_ocsf(path)
    except json.JSONDecodeError as e:
        raise ValueError(f"{path}: invalid JSON: {e}") from e
    events, invalid = [], 0
    for i, ev in enumerate(raw, 1):
        if schema is not None:
            for err in schema.validate_event(ev):
                invalid += 1
                print(f"[OCSF   ] {path.name} event {i}: {err}", file=sys.stderr)
        try:
            events.append(normalize(ev, args.ocsf_source))
        except OcsfMappingError as e:
            raise OcsfMappingError(f"{path}: event {i}: {e}") from e
    return events, invalid


def cmd_replay(args) -> int:
    root, catalog = _ctx(args)
    res = _behaviors(root, None)
    bs = [b for b in res.behaviors if not args.behavior or b.id == args.behavior]
    try:
        schema = _ocsf_schema(root) if args.validate_ocsf else None
        events, invalid = _load_replay_events(args, schema)
    except (OcsfMappingError, ValueError) as e:
        print(f"replay: {e}", file=sys.stderr)
        return 2
    alerts = Engine(bs, catalog).run(events)
    try:
        executor = _executor(args)
    except ValueError as e:
        print(f"replay: {e}", file=sys.stderr)
        return 2
    by_id = {b.id: b for b in bs}
    for a in alerts:
        actions = run_plan(executor, a, plan(by_id[a.behavior_id], a)) if executor else None
        if args.output_format == "ocsf":
            rec = to_detection_finding(a, by_id[a.behavior_id], catalog, response=actions,
                                       atlas_in_attacks=args.ocsf_atlas_in_attacks)
            for err in schema.validate_event(rec) if schema is not None else []:
                invalid += 1
                print(f"[OCSF   ] finding {a.behavior_id}: {err}", file=sys.stderr)
        else:
            rec = a.to_dict()
            if actions is not None:
                rec["response"] = [vars(p) for p in actions]
        print(json.dumps(rec))
    fmt = "" if args.input_format == args.output_format == "native" else \
        f" ({args.input_format} -> {args.output_format})"
    print(f"# {len(alerts)} alert(s) from {len(events)} event(s){fmt}", file=sys.stderr)
    if invalid:
        print(f"# {invalid} OCSF validation error(s)", file=sys.stderr)
        return 2
    if args.expect:
        ok = (len(alerts) > 0) == (args.expect == "alert")
        print(f"# expect={args.expect}: {'PASS' if ok else 'FAIL'}", file=sys.stderr)
        return 0 if ok else 1
    return 0


def cmd_test(args) -> int:
    root, _ = _ctx(args)
    res = _behaviors(root, None)
    failed = 0
    rows = []
    for b in res.behaviors:
        for fixture, expect, ok, n in run_tests(b, root):
            failed += not ok
            rows.append([b.id, Path(fixture).name, expect, n, "PASS" if ok else "FAIL"])
    print(_table(rows, ["BEHAVIOR", "FIXTURE", "EXPECT", "ALERTS", "RESULT"]))
    print(f"\n{len(rows) - failed}/{len(rows)} passed")
    return 1 if failed or res.errors else 0


def cmd_atlas_sync(args) -> int:
    root, _ = (Path(args.root).resolve() if args.root else find_root()), None
    dest = Path(args.catalog) if args.catalog else root / "atlas" / "catalog.yaml"
    lock = root / "atlas" / "atlas-data.lock"
    try:
        cat = sync(dest, lock, local_file=Path(args.file) if args.file else None)
    except OSError as e:
        print(f"sync failed: {e}. Download dist/ATLAS.yaml from mitre-atlas/atlas-data and run "
              f"`abm atlas-sync --file ATLAS.yaml`.", file=sys.stderr)
        return 1
    print(f"ATLAS {cat.version}: {len(cat.tactics)} tactics, {len(cat.techniques)} techniques, "
          f"{len(cat.mitigations)} mitigations -> {dest}")
    return 0


# ---------------------------------------------------------------- parser
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="abm", description="ATLAS Behavior Map")
    p.add_argument("--version", action="version", version=f"abm {__version__}")
    p.add_argument("--root", help="project root (default: auto-detect)")
    p.add_argument("--catalog", help="ATLAS catalog YAML (default: atlas/catalog.yaml)")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("validate", help="schema + ATLAS ID resolution + fixtures")
    s.add_argument("path", nargs="?")
    s.add_argument("--run-tests", action="store_true", help="also replay declared test fixtures")
    s.add_argument("-q", "--quiet", action="store_true", help="errors only")
    s.set_defaults(fn=cmd_validate)

    s = sub.add_parser("compile", help="compile behaviors to SIEM rules")
    s.add_argument("--target", choices=[*TARGETS, "all"], default="all")
    s.add_argument("--out")
    s.add_argument("--path")
    s.add_argument("--include-deprecated", action="store_true")
    s.add_argument("--profile", choices=list(KQL_PROFILES), default="default",
                   help="KQL table names: default, or sentinel (custom tables end in _CL). "
                        "The sentinel target always uses the sentinel profile")
    s.set_defaults(fn=cmd_compile)

    s = sub.add_parser("sentinel-build",
                       help="generate the Microsoft Sentinel solution (rules, tables/DCRs, workbook, playbook)")
    s.add_argument("--out", help="solution folder (default: integrations/sentinel)")
    s.add_argument("--layer", help="Navigator layer JSON for the workbook (default: computed, as abm coverage)")
    s.add_argument("--check", action="store_true", help="write nothing; exit 1 if the folder is out of date")
    s.set_defaults(fn=cmd_sentinel_build)

    s = sub.add_parser("sentinel-validate", help="check a Sentinel solution folder before packaging")
    s.add_argument("path", nargs="?", help="solution folder (default: integrations/sentinel)")
    s.set_defaults(fn=cmd_sentinel_validate)

    s = sub.add_parser("map", help="show behavior -> ATLAS mapping")
    s.add_argument("--behavior")
    s.add_argument("--technique", help="filter by technique id prefix, e.g. AML.T0051")
    s.add_argument("--format", choices=["table", "json"], default="table")
    s.set_defaults(fn=cmd_map)

    s = sub.add_parser("coverage", help="coverage reports + Navigator layer")
    s.add_argument("--matrix", default="atlas", choices=["atlas"])
    s.add_argument("--out", help="report directory (default: reports/)")
    s.add_argument("--layer", help="Navigator layer path (default: reports/atlas-layer.json)")
    s.set_defaults(fn=cmd_coverage)

    s = sub.add_parser("gaps", help="list uncovered techniques")
    s.add_argument("--tactic")
    s.add_argument("--below", type=int, default=1, help="list techniques scoring below N (default 1)")
    s.set_defaults(fn=cmd_gaps)

    s = sub.add_parser("replay", help="run behaviors over a JSONL telemetry file")
    s.add_argument("--fixture", required=True)
    s.add_argument("--behavior")
    s.add_argument("--expect", choices=["alert", "no_alert"])
    s.add_argument("--respond", action="store_true", help="plan response actions (dry-run default)")
    s.add_argument("--webhook", help="https SOAR webhook for auto-approved actions")
    s.add_argument("--xsoar", metavar="URL",
                   help="create a Cortex XSOAR incident per alert (implies --respond); "
                        "reads XSOAR_API_KEY and, for XSOAR 8, XSOAR_API_KEY_ID from the environment")
    s.add_argument("--xsoar-incident-type", default="AI Security Alert", help="XSOAR incident type")
    s.add_argument("--input-format", choices=["native", "ocsf"], default="native",
                   help="native: normalized JSONL (default); ocsf: OCSF 1.8.0 events (JSONL or JSON array)")
    s.add_argument("--output-format", choices=["native", "ocsf"], default="native",
                   help="native: abm alert JSON (default); ocsf: OCSF Detection Finding per alert")
    s.add_argument("--ocsf-source", choices=sorted(OCSF_SOURCES),
                   help="force the source mapping for OCSF input (default: metadata.log_name, "
                        "else best match on the event's attributes)")
    s.add_argument("--ocsf-atlas-in-attacks", action="store_true",
                   help="also list ATLAS techniques in the finding's attacks[] (ATT&CK bridge only by default)")
    s.add_argument("--validate-ocsf", action="store_true",
                   help="check OCSF input and output against the vendored OCSF 1.8.0 schema + abm extension")
    s.set_defaults(fn=cmd_replay)

    s = sub.add_parser("test", help="run every behavior's declared fixture tests")
    s.set_defaults(fn=cmd_test)

    s = sub.add_parser("atlas-sync", help="import official ATLAS release into the catalog")
    s.add_argument("--file", help="local ATLAS.yaml instead of downloading")
    s.set_defaults(fn=cmd_atlas_sync)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
