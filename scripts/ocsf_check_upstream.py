"""Check the current OCSF release for AI objects before changing the abm extension.

Compares the vendored OCSF base (schemas/ocsf/base/) with the newest release on schema.ocsf.io
(or with a local export file) and reports:

* whether a newer OCSF release exists;
* every AI-related core object, profile and attribute in that release (ai_*, message_context,
  *_tokens, embedding_model, attack/ATLAS wording, ...), and how each differs from the vendored
  copy;
* abm extension attributes and objects whose names now exist in the core dictionary. Those
  should move to the core definition (extend, don't duplicate) before the next extension release.

Needs network access to schema.ocsf.io unless --export is given. Exit code 0 = vendored base is
current and no overlap, 1 = action needed, 2 = could not fetch.

    python scripts/ocsf_check_upstream.py
    python scripts/ocsf_check_upstream.py --export ocsf-1.9.0.json
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

from ocsf_vendor_base import build  # noqa: E402

from abm.ocsf_schema import OcsfSchema  # noqa: E402

SERVER = "https://schema.ocsf.io"
AI_RE = re.compile(r"(^ai_|^message_context$|_tokens$|^embedding_model$|^llm|prompt|^mcp|agentic)")
AI_TEXT_RE = re.compile(r"\b(AI|LLM|ATLAS|MCP|prompt|agentic|embedding)\b")


def _get(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"Accept": "application/json",  # noqa: S310
                                               "User-Agent": "abm-ocsf-check"})
    with urllib.request.urlopen(req, timeout=60) as r:  # noqa: S310 (https constant)
        return r.read()


def fetch_latest() -> tuple[str, dict]:
    version = json.loads(_get(f"{SERVER}/api/version"))["version"]
    for path in (f"{version}/export/v2/schema", f"{version}/export/schema", "export/schema"):
        try:
            return version, json.loads(_get(f"{SERVER}/{path}"))
        except (OSError, ValueError):
            continue
    raise OSError(f"could not download the schema export for OCSF {version}")


def ai_surface(export: dict) -> dict[str, object]:
    """AI-related slice of a compiled OCSF export."""
    out: dict[str, object] = {}
    for name, o in export.get("objects", {}).items():
        if AI_RE.search(name) or AI_TEXT_RE.search(o.get("description", "")):
            out[f"object:{name}"] = sorted(o.get("attributes", {}))
    for name, p in (export.get("profiles") or {}).items():
        if AI_RE.search(name) or AI_TEXT_RE.search(p.get("description", "")):
            out[f"profile:{name}"] = sorted(p.get("attributes") or {})
    attrs = export.get("dictionary", {}).get("attributes", {})
    for name, a in attrs.items():
        if AI_RE.search(name):
            out[f"attribute:{name}"] = a.get("type")
    for name, c in export.get("classes", {}).items():
        ai = sorted(a for a in c.get("attributes", {}) if AI_RE.search(a))
        if ai:
            out[f"class:{name}"] = ai
    return out


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--export", help="local OCSF export JSON instead of downloading the latest")
    a = p.parse_args()
    vendored = OcsfSchema.load(ROOT)
    try:
        if a.export:
            export = json.loads(Path(a.export).read_text(encoding="utf-8"))
            version = export["version"]
        else:
            version, export = fetch_latest()
    except (OSError, ValueError, KeyError) as e:
        print(f"could not fetch the OCSF schema: {e}", file=sys.stderr)
        print("offline? download https://schema.ocsf.io/<version>/export/v2/schema and pass --export")
        return 2

    action = False
    print(f"vendored OCSF base : {vendored.version}")
    print(f"upstream OCSF      : {version}")
    if version != vendored.version:
        action = True
        print(f"-> newer release. Review the AI surface below, then run:\n"
              f"   python scripts/ocsf_vendor_base.py --export <ocsf-{version}.json>")

    print("\nAI-related core definitions upstream:")
    for k, v in sorted(ai_surface(export).items()):
        print(f"  {k}: {v}")

    # compare the AI objects abm extends with the vendored copy
    new_base = dict(build(export, "n/a"))
    for obj in ("ai_model", "message_context", "attack", "technique", "tactic", "mitigation"):
        old = set(vendored.objects[obj].attributes) if obj in vendored.objects else set()
        up = set(new_base.get(f"object:{obj}", {}).get("attributes", {}))
        ext = {n for n, at in vendored.objects.get(obj, None).attributes.items()
               if at.source == "abm"} if obj in vendored.objects else set()
        added, removed = sorted(up - old), sorted((old - ext) - up)
        if added or removed:
            action = True
            print(f"\n{obj}: upstream added {added or '-'}, removed {removed or '-'}")

    core_attrs = set(export.get("dictionary", {}).get("attributes", {}))
    core_objs = set(export.get("objects", {}))
    overlap_attrs = sorted(set(vendored.ext_dictionary) & core_attrs)
    overlap_objs = sorted(set(vendored.ext_objects) & core_objs)
    if overlap_attrs or overlap_objs:
        action = True
        print("\nabm extension names that now exist in the OCSF core (migrate to core):")
        for n in overlap_attrs:
            print(f"  attribute {n}")
        for n in overlap_objs:
            print(f"  object {n}")
    else:
        print("\nno abm extension attribute or object collides with the upstream core")
    print("\nRESULT:", "ACTION NEEDED" if action else "OK (vendored base is current)")
    return 1 if action else 0


if __name__ == "__main__":
    raise SystemExit(main())
