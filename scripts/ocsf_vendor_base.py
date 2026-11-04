"""Vendor the slice of the OCSF core schema that abm validates against.

Input is the compiled schema export from the OCSF server, for example
    curl -o ocsf-1.8.0.json https://schema.ocsf.io/1.8.0/export/v2/schema
(the same file ships inside the `ocsf-json-schema` PyPI wheel as ocsf_json_schema/ocsf/1.8.0.json).

Output: schemas/ocsf/base/ocsf-<version>-subset.json, one JSON record per line so diffs stay readable.
It keeps, for the event classes abm reads or writes, every attribute with its type, object type,
array flag, requirement and enum keys; every core object in the same compact form; the core
dictionary types; and the profile names. Descriptions are dropped.

    python scripts/ocsf_vendor_base.py --export ocsf-1.8.0.json
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CLASSES = ["base_event", "api_activity", "http_activity", "datastore_activity", "authentication",
           "detection_finding"]


def _attr(v: dict) -> dict:
    e: dict = {"t": v.get("type")}
    if v.get("object_type"):
        e["o"] = v["object_type"]
    if v.get("is_array"):
        e["a"] = 1
    if v.get("requirement") == "required":
        e["r"] = 1
    if "enum" in v:
        e["e"] = sorted(v["enum"], key=lambda k: int(k) if k.lstrip("-").isdigit() else 0)
    return e


def _defn(d: dict, with_uid: bool = False) -> dict:
    out: dict = {"attributes": {k: _attr(v) for k, v in sorted(d.get("attributes", {}).items())}}
    if d.get("constraints"):
        out["constraints"] = d["constraints"]
    if with_uid:
        out["uid"] = d.get("uid")
        out["category"] = d.get("category")
    return out


def build(export: dict, source_sha: str) -> list[tuple[str, object]]:
    lines: list[tuple[str, object]] = [
        ("version", export["version"]),
        ("source", {"export": f"https://schema.ocsf.io/{export['version']}/export/v2/schema",
                    "sha256": source_sha}),
        ("profiles", sorted(export.get("profiles", {}))),
        ("types", {k: (v.get("type") or k) for k, v in
                   sorted(export["dictionary"]["types"]["attributes"].items())}),
        ("categories", {k: v["uid"] for k, v in sorted(export["categories"]["attributes"].items())}),
    ]
    dict_attrs = export["dictionary"]["attributes"]
    lines.append(("dictionary", {k: {kk: vv for kk, vv in _attr(v).items() if kk in ("t", "o", "a")}
                                 for k, v in sorted(dict_attrs.items())}))
    for name in CLASSES:
        lines.append((f"class:{name}", _defn(export["classes"][name], with_uid=True)))
    for name in sorted(export["objects"]):
        lines.append((f"object:{name}", _defn(export["objects"][name])))
    return lines


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--export", required=True, help="OCSF export v2 JSON (schema.ocsf.io/<v>/export/v2/schema)")
    p.add_argument("--out-dir", default=str(ROOT / "schemas" / "ocsf" / "base"))
    a = p.parse_args()
    raw = Path(a.export).read_bytes()
    export = json.loads(raw)
    lines = build(export, hashlib.sha256(raw).hexdigest())
    out = Path(a.out_dir) / f"ocsf-{export['version']}-subset.json"
    body = ",\n".join(f"{json.dumps(k)}: {json.dumps(v, sort_keys=True, separators=(',', ':'))}"
                      for k, v in lines)
    out.write_text("{\n" + body + "\n}\n", encoding="utf-8", newline="\n")
    print(f"wrote {out} ({out.stat().st_size} bytes) from OCSF {export['version']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
