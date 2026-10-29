"""ATLAS catalog: tactic/technique/mitigation lookup, plus import from the official atlas-data release."""

from __future__ import annotations

import hashlib
import urllib.request
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml

ATLAS_DATA_URL = "https://raw.githubusercontent.com/mitre-atlas/atlas-data/main/dist/ATLAS.yaml"


@dataclass(frozen=True)
class Entry:
    id: str
    name: str
    tactics: tuple[str, ...] = ()
    parent: str | None = None


@dataclass
class AtlasCatalog:
    source: str
    version: str
    tactics: dict[str, Entry] = field(default_factory=dict)
    techniques: dict[str, Entry] = field(default_factory=dict)
    mitigations: dict[str, Entry] = field(default_factory=dict)

    # ---- lookup -----------------------------------------------------------
    def has(self, atlas_id: str) -> bool:
        return (
            atlas_id in self.tactics or atlas_id in self.techniques or atlas_id in self.mitigations
        )

    def name(self, atlas_id: str) -> str:
        for table in (self.techniques, self.tactics, self.mitigations):
            if atlas_id in table:
                e = table[atlas_id]
                if e.parent and e.parent in self.techniques:
                    return f"{self.techniques[e.parent].name}: {e.name}"
                return e.name
        return "<unresolved>"

    def tactics_for(self, technique_id: str) -> tuple[str, ...]:
        e = self.techniques.get(technique_id)
        if not e:
            return ()
        if not e.tactics and e.parent:  # sub-techniques inherit the parent's tactics
            return self.tactics_for(e.parent)
        return e.tactics

    # ---- io ---------------------------------------------------------------
    @classmethod
    def load(cls, path: Path) -> AtlasCatalog:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        cat = cls(source=str(data.get("source", "unknown")), version=str(data.get("version", "")))
        for t in data.get("tactics", []):
            cat.tactics[t["id"]] = Entry(t["id"], t["name"])
        for t in data.get("techniques", []):
            cat.techniques[t["id"]] = Entry(
                t["id"], t["name"], tuple(t.get("tactics", [])), t.get("parent")
            )
        for m in data.get("mitigations", []):
            cat.mitigations[m["id"]] = Entry(m["id"], m["name"])
        return cat

    def dump(self, path: Path) -> None:
        def row(e: Entry) -> dict[str, Any]:
            d: dict[str, Any] = {"id": e.id, "name": e.name}
            if e.tactics:
                d["tactics"] = list(e.tactics)
            if e.parent:
                d["parent"] = e.parent
            return d

        out = {
            "source": self.source,
            "version": self.version,
            "tactics": [row(e) for e in self.tactics.values()],
            "techniques": [row(e) for e in sorted(self.techniques.values(), key=lambda e: e.id)],
            "mitigations": [row(e) for e in sorted(self.mitigations.values(), key=lambda e: e.id)],
        }
        path.write_text(yaml.safe_dump(out, sort_keys=False, width=120), encoding="utf-8")

    # ---- upstream import ---------------------------------------------------
    @classmethod
    def from_atlas_data(cls, raw: str) -> AtlasCatalog:
        """Parse the official dist/ATLAS.yaml (handles both matrix-nested and flat layouts)."""
        data = yaml.safe_load(raw)
        version = str(data.get("version", "unknown"))
        matrices = data.get("matrices") or [data]

        cat = cls(source="mitre-atlas/atlas-data", version=version)
        for mx in matrices:
            for t in mx.get("tactics", []) or []:
                cat.tactics[t["id"]] = Entry(t["id"], t["name"])
            techs = mx.get("techniques", []) or []
            by_id = {t["id"]: t for t in techs}
            for t in techs:
                parent = t.get("specializes") or t.get("subtechnique-of")
                tactics = t.get("tactics") or (by_id.get(parent, {}).get("tactics") if parent else [])
                cat.techniques[t["id"]] = Entry(t["id"], t["name"], tuple(tactics or []), parent)
            for m in mx.get("mitigations", []) or []:
                cat.mitigations[m["id"]] = Entry(m["id"], m["name"])
        if not cat.techniques:
            raise ValueError("no techniques found: unrecognized ATLAS.yaml layout")
        return cat


def sync(dest: Path, lock: Path, url: str = ATLAS_DATA_URL, local_file: Path | None = None) -> AtlasCatalog:
    """Fetch (or import) ATLAS.yaml, write catalog + lock file with checksum."""
    if local_file:
        raw = local_file.read_text(encoding="utf-8")
        origin = str(local_file)
    else:
        with urllib.request.urlopen(url, timeout=30) as resp:  # noqa: S310 (fixed https URL)
            raw = resp.read().decode("utf-8")
        origin = url
    cat = AtlasCatalog.from_atlas_data(raw)
    cat.dump(dest)
    lock.write_text(
        yaml.safe_dump(
            {
                "origin": origin,
                "version": cat.version,
                "sha256": hashlib.sha256(raw.encode("utf-8")).hexdigest(),
                "synced_at": datetime.now(UTC).isoformat(timespec="seconds"),
                "counts": {
                    "tactics": len(cat.tactics),
                    "techniques": len(cat.techniques),
                    "mitigations": len(cat.mitigations),
                },
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )
    return cat
