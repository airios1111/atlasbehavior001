"""OCSF schema model used to check abm's OCSF input/output and the abm extension itself.

Loads two things from the project tree:

* ``schemas/ocsf/base/ocsf-<version>-subset.json``: a compact slice of the OCSF core schema
  (event classes abm reads or writes, every core object, the dictionary and the type table),
  vendored by ``scripts/ocsf_vendor_base.py`` from the official schema export.
* ``schemas/ocsf/abm-extension/``: the abm extension in OCSF source layout (``extension.json``,
  ``dictionary.json``, ``objects/``, ``events/``). Files whose ``extends`` names a core object or
  class and that carry no ``name`` of their own are patches of that core definition.

This is a structural validator, not a replacement for the OCSF server: it checks attribute names,
requirements, ``at_least_one`` constraints, primitive types, enum membership and the class/type
UID arithmetic. It is strict enough to keep the fixtures and the Detection Finding output honest.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

OCSF_VERSION = "1.8.0"
BASE_REL = Path("schemas/ocsf/base") / f"ocsf-{OCSF_VERSION}-subset.json"
EXT_REL = Path("schemas/ocsf/abm-extension")

# Attributes that only become required when the profile that contributes them is declared in
# metadata.profiles. The compiled export marks them required on every class.
PROFILE_REQUIRED = {"cloud": "cloud", "osint": "osint"}
# Core classes that receive ai_model / message_context through the ai_operation profile.
AI_OPERATION_CLASSES = {"api_activity", "datastore_activity", "process_activity"}
AI_OPERATION_ATTRS = {"ai_model", "message_context"}

_INT_TYPES = {"integer_t", "long_t", "timestamp_t", "port_t"}


@dataclass
class Attr:
    type: str                       # primitive *_t or "object_t"
    object_type: str | None = None  # for object_t
    is_array: bool = False
    required: bool = False
    enum: list[str] | None = None
    source: str = "core"            # core | abm


@dataclass
class Defn:
    name: str
    attributes: dict[str, Attr] = field(default_factory=dict)
    constraints: dict[str, list[str]] = field(default_factory=dict)
    uid: int | None = None
    category: str | None = None
    source: str = "core"


def _attr(e: dict[str, Any], source: str = "core") -> Attr:
    return Attr(type=e["t"], object_type=e.get("o"), is_array=bool(e.get("a")),
                required=bool(e.get("r")), enum=e.get("e"), source=source)


class OcsfSchema:
    def __init__(self, base: dict[str, Any], ext_dir: Path | None):
        self.version: str = base["version"]
        self.base_source: dict[str, Any] = base.get("source", {})
        self.types: dict[str, str] = base["types"]
        self.categories: dict[str, int] = base["categories"]
        self.profiles: set[str] = set(base["profiles"])
        self.core_dictionary: dict[str, dict[str, Any]] = base["dictionary"]
        self.classes: dict[str, Defn] = {}
        self.objects: dict[str, Defn] = {}
        for key, val in base.items():
            if key.startswith("class:"):
                name = key[6:]
                self.classes[name] = Defn(name, {k: _attr(v) for k, v in val["attributes"].items()},
                                          val.get("constraints", {}), val.get("uid"), val.get("category"))
            elif key.startswith("object:"):
                name = key[7:]
                self.objects[name] = Defn(name, {k: _attr(v) for k, v in val["attributes"].items()},
                                          val.get("constraints", {}))
        self.extension: dict[str, Any] = {}
        self.ext_dictionary: dict[str, dict[str, Any]] = {}
        self.ext_objects: list[str] = []
        self.patches: list[tuple[str, str]] = []  # (kind, target)
        self.load_errors: list[str] = []
        if ext_dir is not None:
            self._load_extension(ext_dir)

    # ------------------------------------------------------------------ loading
    @classmethod
    def load(cls, root: Path, with_extension: bool = True) -> OcsfSchema:
        base = json.loads((root / BASE_REL).read_text(encoding="utf-8"))
        return cls(base, root / EXT_REL if with_extension else None)

    def _dict_attr(self, name: str) -> tuple[Attr | None, str]:
        if name in self.ext_dictionary:
            d = self.ext_dictionary[name]
            t = d.get("type", "")
            if t.endswith("_t"):
                return Attr(type=t, is_array=bool(d.get("is_array")), source="abm"), "abm"
            return Attr(type="object_t", object_type=t, is_array=bool(d.get("is_array")),
                        source="abm"), "abm"
        if name in self.core_dictionary:
            return _attr(self.core_dictionary[name]), "core"
        return None, ""

    def _ref_attrs(self, owner: str, raw: dict[str, Any]) -> dict[str, Attr]:
        out: dict[str, Attr] = {}
        for name, spec in raw.items():
            a, _ = self._dict_attr(name)
            if a is None:
                self.load_errors.append(f"{owner}: attribute '{name}' is in neither the abm nor the core dictionary")
                continue
            a.required = (spec or {}).get("requirement") == "required"
            a.source = "abm"
            out[name] = a
        return out

    def _load_extension(self, ext_dir: Path) -> None:
        self.extension = json.loads((ext_dir / "extension.json").read_text(encoding="utf-8"))
        self.ext_dictionary = json.loads((ext_dir / "dictionary.json").read_text(encoding="utf-8"))["attributes"]
        for name in self.ext_dictionary:
            if name in self.core_dictionary:
                self.load_errors.append(f"dictionary: '{name}' redefines a core OCSF attribute")
        obj_files = sorted((ext_dir / "objects").glob("*.json"))
        defs = [(f, json.loads(f.read_text(encoding="utf-8"))) for f in obj_files]
        # new objects first (patch targets may be new objects in principle), parents before children
        new = [(f, d) for f, d in defs if d.get("name")]
        pending = list(new)
        for _ in range(len(pending) + 1):
            rest = []
            for f, d in pending:
                parent = d.get("extends", "object")
                if parent not in ("object", "_entity") and parent not in self.objects:
                    rest.append((f, d))
                    continue
                attrs = dict(self.objects[parent].attributes) if parent in self.objects else {}
                cons = dict(self.objects[parent].constraints) if parent in self.objects else {}
                attrs.update(self._ref_attrs(f"objects/{f.name}", d.get("attributes", {})))
                cons.update(d.get("constraints", {}))
                if d["name"] in self.objects:
                    self.load_errors.append(f"objects/{f.name}: new object '{d['name']}' collides with a core object")
                self.objects[d["name"]] = Defn(d["name"], attrs, cons, source="abm")
                self.ext_objects.append(d["name"])
            pending = rest
        for f, d in pending:
            self.load_errors.append(f"objects/{f.name}: parent '{d.get('extends')}' not found")
        for f, d in defs:
            if d.get("name"):
                continue
            target = d.get("extends")
            if target not in self.objects:
                self.load_errors.append(f"objects/{f.name}: patch target '{target}' is not a core object")
                continue
            self.objects[target].attributes.update(self._ref_attrs(f"objects/{f.name}", d.get("attributes", {})))
            self.patches.append(("object", target))
        for f in sorted((ext_dir / "events").rglob("*.json")):
            d = json.loads(f.read_text(encoding="utf-8"))
            target = d.get("extends")
            rel = f.relative_to(ext_dir).as_posix()
            if d.get("name") and d.get("name") != target:
                self.load_errors.append(f"{rel}: new event classes are not supported by abm's validator")
                continue
            if target not in self.classes:
                self.load_errors.append(f"{rel}: patch target '{target}' is not a vendored core class")
                continue
            self.classes[target].attributes.update(self._ref_attrs(rel, d.get("attributes", {})))
            self.patches.append(("class", target))
        for o in self.objects.values():
            for an, a in o.attributes.items():
                if a.type == "object_t" and a.object_type not in self.objects and a.object_type != "object":
                    self.load_errors.append(f"object {o.name}.{an}: unknown object type '{a.object_type}'")

    # ------------------------------------------------------------------ lookup
    def class_by_uid(self, uid: int) -> Defn | None:
        return next((c for c in self.classes.values() if c.uid == uid), None)

    def resolve(self, class_name: str, path: str) -> Attr:
        """Resolve a dotted path (``a.b[0].c``) against a class; raises KeyError if invalid."""
        defn = self.classes[class_name]
        attr: Attr | None = None
        for part in path.split("."):
            name, idx = (part[:-3], True) if part.endswith("[0]") else (part, False)
            if defn is None:
                raise KeyError(f"{path}: '{name}' is below a non-object attribute")
            if defn.name == "object":  # free-form (unmapped)
                return Attr(type="json_t")
            if name not in defn.attributes:
                raise KeyError(f"{path}: '{name}' is not an attribute of {defn.name}")
            attr = defn.attributes[name]
            if idx and not attr.is_array:
                raise KeyError(f"{path}: '{name}' is not an array")
            if attr.type == "object_t":
                defn = self.objects.get(attr.object_type or "") or (
                    Defn("object") if attr.object_type == "object" else None)
            else:
                defn = None
        if attr is None:
            raise KeyError(f"empty path: {path!r}")
        return attr

    # ------------------------------------------------------------------ validation
    def validate_event(self, ev: dict[str, Any]) -> list[str]:
        errs: list[str] = []
        uid = ev.get("class_uid")
        cls = self.class_by_uid(uid) if isinstance(uid, int) else None
        if cls is None:
            return [f"class_uid {uid!r} is not a vendored OCSF class"]
        cat = self.categories.get(cls.category or "")
        if ev.get("category_uid") != cat:
            errs.append(f"category_uid {ev.get('category_uid')!r} != {cat} for {cls.name}")
        act = ev.get("activity_id")
        if isinstance(act, int) and ev.get("type_uid") != uid * 100 + act:
            errs.append(f"type_uid {ev.get('type_uid')!r} != class_uid*100+activity_id ({uid * 100 + act})")
        profiles = set((ev.get("metadata") or {}).get("profiles") or [])
        for p in profiles:
            if p not in self.profiles and not p.startswith(f"{self.extension.get('name', '')}/"):
                errs.append(f"metadata.profiles: unknown profile '{p}'")
        skip_required = {attr for prof, attr in PROFILE_REQUIRED.items() if prof not in profiles}
        if cls.name in AI_OPERATION_CLASSES and AI_OPERATION_ATTRS & set(ev) and "ai_operation" not in profiles:
            errs.append("ai_model/message_context used without 'ai_operation' in metadata.profiles")
        if any(k.endswith("_dt") for k in ev) and "datetime" not in profiles:
            errs.append("*_dt attributes used without 'datetime' in metadata.profiles")
        self._check(cls, ev, cls.name, errs, skip_required)
        return errs

    def _check(self, defn: Defn, obj: dict[str, Any], where: str, errs: list[str],
               skip_required: set[str] = frozenset()) -> None:  # type: ignore[assignment]
        for name, a in defn.attributes.items():
            if a.required and name not in obj and name not in skip_required:
                errs.append(f"{where}: missing required '{name}'")
        group = defn.constraints.get("at_least_one")
        if group and not any(g in obj for g in group):
            errs.append(f"{where}: needs at least one of {group}")
        for key, val in obj.items():
            a = defn.attributes.get(key)
            if a is None:
                errs.append(f"{where}: unknown attribute '{key}'")
                continue
            if a.is_array:
                if not isinstance(val, list):
                    errs.append(f"{where}.{key}: expected an array")
                    continue
                for i, item in enumerate(val):
                    self._value(a, item, f"{where}.{key}[{i}]", errs)
            else:
                self._value(a, val, f"{where}.{key}", errs)

    def _value(self, a: Attr, val: Any, where: str, errs: list[str]) -> None:
        if a.type == "object_t":
            if a.object_type == "object":
                if not isinstance(val, dict):
                    errs.append(f"{where}: expected an object")
                return
            if not isinstance(val, dict):
                errs.append(f"{where}: expected object {a.object_type}")
                return
            sub = self.objects.get(a.object_type or "")
            if sub is None:
                errs.append(f"{where}: unknown object type {a.object_type}")
                return
            self._check(sub, val, where, errs)
            return
        base = self.types.get(a.type, a.type)
        if base == "json_t":
            return
        ok = {
            "string_t": isinstance(val, str),
            "boolean_t": isinstance(val, bool),
            "float_t": isinstance(val, (int, float)) and not isinstance(val, bool),
        }.get(base)
        if base in _INT_TYPES or a.type in _INT_TYPES:
            ok = isinstance(val, int) and not isinstance(val, bool)
        if ok is None:
            ok = True
        if not ok:
            errs.append(f"{where}: {val!r} is not {a.type}")
            return
        if a.enum and isinstance(val, int) and str(val) not in a.enum:
            errs.append(f"{where}: {val} is not a defined enum value {a.enum}")

    # ------------------------------------------------------------------ extension self-check
    def check_extension(self) -> list[str]:
        errs = list(self.load_errors)
        ext = self.extension
        for k in ("caption", "name", "uid", "version"):
            if k not in ext:
                errs.append(f"extension.json: missing '{k}'")
        if ext.get("name") in self.profiles or ext.get("name") in ("linux", "win", "macos"):
            errs.append("extension.json: name collides with a core extension/profile")
        used = set()
        for o in self.objects.values():
            used.update(n for n, a in o.attributes.items() if a.source == "abm")
        for c in self.classes.values():
            used.update(n for n, a in c.attributes.items() if a.source == "abm")
        for name in self.ext_dictionary:
            if name not in used:
                errs.append(f"dictionary: '{name}' is defined but not used by any object or class patch")
        for name, d in self.ext_dictionary.items():
            if not d.get("caption") or not d.get("description"):
                errs.append(f"dictionary: '{name}' needs caption and description")
            t = d.get("type", "")
            if t.endswith("_t") and t not in self.types:
                errs.append(f"dictionary: '{name}' has unknown type {t}")
            if not t.endswith("_t") and t not in self.objects:
                errs.append(f"dictionary: '{name}' references unknown object {t}")
            if name.endswith("_id"):
                errs.append(f"dictionary: '{name}' ends in _id, which OCSF reserves for enum siblings")
        return errs
