"""abm command-line interface."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from abm import __version__
from abm.catalog import AtlasCatalog, sync
from abm.compilers import TARGETS
from abm.coverage import SCORE_LABEL, compute, gaps, write_reports
from abm.engine import Engine, load_events, run_tests
from abm.loader import find_root, load_behaviors
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
        fn, ext = TARGETS[t]
        out = out_root / t if (args.target == "all" or not args.out) else out_root
        out.mkdir(parents=True, exist_ok=True)
        for b in res.behaviors:
            if b.status.value == "deprecated" and not args.include_deprecated:
                continue
            (out / f"{b.id}{ext}").write_text(fn(b), encoding="utf-8")
            n += 1
    print(f"compiled {n} rule(s) -> {out_root}")
    return 1 if res.errors else 0


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


def cmd_replay(args) -> int:
    root, catalog = _ctx(args)
    res = _behaviors(root, None)
    bs = [b for b in res.behaviors if not args.behavior or b.id == args.behavior]
    events = load_events(Path(args.fixture))
    alerts = Engine(bs, catalog).run(events)
    try:
        executor = _executor(args)
    except ValueError as e:
        print(f"replay: {e}", file=sys.stderr)
        return 2
    by_id = {b.id: b for b in bs}
    for a in alerts:
        rec = a.to_dict()
        if executor:
            rec["response"] = [vars(p) for p in run_plan(executor, a, plan(by_id[a.behavior_id], a))]
        print(json.dumps(rec))
    print(f"# {len(alerts)} alert(s) from {len(events)} event(s)", file=sys.stderr)
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
    s.set_defaults(fn=cmd_compile)

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
