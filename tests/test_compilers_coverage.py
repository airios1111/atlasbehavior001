import json

import yaml

from abm.catalog import AtlasCatalog
from abm.compilers import TARGETS
from abm.compilers.sigma import rule_id
from abm.coverage import compute, gaps, navigator_layer
from abm.loader import load_behaviors
from abm.models import TechniqueRef
from abm.validator import validate


def test_every_behavior_compiles_to_every_target(behaviors):
    for b in behaviors.values():
        for name, (fn, _) in TARGETS.items():
            out = fn(b)
            assert b.id in out and b.primary_technique.lower() in out.lower(), (name, b.id)


def test_sigma_is_valid_yaml_with_atlas_tags(behaviors):
    docs = list(yaml.safe_load_all(TARGETS["sigma"][0](behaviors["BHV-EXF-003"])))
    assert docs[0]["id"] == rule_id("BHV-EXF-003")
    assert "atlas.aml.t0024.002" in docs[0]["tags"]
    assert docs[1]["correlation"]["condition"] == {"gt": 5000}


def test_kql_threshold_shape(behaviors):
    q = TARGETS["kql"][0](behaviors["BHV-EXF-003"])
    assert "summarize" in q and "bin(TimeGenerated, 1h)" in q
    assert "RequestCount > 5000" in q and 'PrincipalId !in ("sp-batch-eval"' in q


def test_seed_repo_validates_clean(root, catalog):
    findings = validate(load_behaviors(root / "behaviors"), catalog, root)
    assert [f for f in findings if f.level == "error"] == []


def test_drift_detected_against_catalog_without_technique(root, catalog):
    pruned = AtlasCatalog(catalog.source, catalog.version, dict(catalog.tactics),
                          {k: v for k, v in catalog.techniques.items() if k != "AML.T0029"},
                          dict(catalog.mitigations))
    errs = [f for f in validate(load_behaviors(root / "behaviors"), pruned, root) if f.level == "error"]
    assert any("AML.T0029" in f.message for f in errs)


def test_coverage_scores(behaviors, catalog, root):
    cov = compute(list(behaviors.values()), catalog, root)
    assert cov["AML.T0024.002"].score == 3   # stable + auto response + replay passing
    assert cov["AML.T0053"].score == 2       # test status
    assert cov["AML.T0034"].score == 1       # experimental w/ mitigations
    assert cov["AML.T0040"].score == 2       # BHV-MA-001/-002 map it as primary
    assert all(g.score == 0 for g in gaps(cov))


def _precondition_probe(behaviors, catalog):
    """A test-status behavior whose only ref to an otherwise unmapped technique is a precondition.
    Built synthetically because every precondition in the repo is also mapped as primary elsewhere."""
    mapped = {t.id for b in behaviors.values() for t in b.atlas.techniques}
    unmapped = sorted(t for t in catalog.techniques if t not in mapped)[0]
    base = behaviors["BHV-AG-008"]  # status test, field_match, no fixtures needed for scoring
    atlas = base.atlas.model_copy(update={"techniques": [
        *base.atlas.techniques, TechniqueRef(id=unmapped, relationship="precondition")]})
    return base.model_copy(update={"id": "BHV-AG-999", "atlas": atlas, "tests": []}), unmapped


def test_precondition_refs_do_not_count(behaviors, catalog, root):
    probe, unmapped = _precondition_probe(behaviors, catalog)
    cov = compute([*behaviors.values(), probe], catalog, root)
    assert cov[unmapped].score == 0 and cov[unmapped].behaviors == []
    assert "BHV-AG-999" in cov[probe.primary_technique].behaviors   # primary still counts


def test_every_tactic_has_a_declared_detection(behaviors, catalog, root):
    """Each ATLAS tactic needs a behavior that declares it, whose primary technique belongs to it,
    at score >= 2. Stricter than `abm gaps`, which also credits a technique to a tactic through
    secondary mappings on behaviors filed under other tactics."""
    from abm.coverage import _behavior_score

    scores = {b.id: _behavior_score(b, root)[0] for b in behaviors.values()}
    missing = [
        f"{tac} {entry.name}" for tac, entry in catalog.tactics.items()
        if not any(
            tac in b.atlas.tactics and tac in catalog.tactics_for(b.primary_technique)
            and scores[b.id] >= 2
            for b in behaviors.values()
        )
    ]
    assert not missing, f"tactics without a declared detection: {missing}"


def test_navigator_layer(behaviors, catalog, root):
    probe, unmapped = _precondition_probe(behaviors, catalog)
    layer = navigator_layer(compute([*behaviors.values(), probe], catalog, root), catalog)
    json.dumps(layer)
    ids = {t["techniqueID"] for t in layer["techniques"]}
    assert "AML.T0051.000" in ids and unmapped not in ids


def test_atlas_data_import_parses_matrix_layout():
    raw = yaml.safe_dump({
        "id": "ATLAS", "version": "9.9.9",
        "matrices": [{
            "tactics": [{"id": "AML.TA0010", "name": "Exfiltration"}],
            "techniques": [
                {"id": "AML.T0024", "name": "Exfil via API", "tactics": ["AML.TA0010"]},
                {"id": "AML.T0024.002", "name": "Extract Model", "specializes": "AML.T0024"},
            ],
            "mitigations": [{"id": "AML.M0004", "name": "Restrict Queries"}],
        }],
    })
    cat = AtlasCatalog.from_atlas_data(raw)
    assert cat.version == "9.9.9"
    assert cat.tactics_for("AML.T0024.002") == ("AML.TA0010",)  # inherited from parent
    assert cat.name("AML.T0024.002") == "Exfil via API: Extract Model"


def test_readme_coverage_table_matches_behaviors(root, behaviors):
    import re

    readme = (root / "README.md").read_text(encoding="utf-8")
    table = readme[readme.index("## Coverage Snapshot"):readme.index("## Repository Structure")]
    listed = set(re.findall(r"^\| (BHV-[A-Z0-9]+-\d{3}) \|", table, flags=re.M))  # C2 has a digit
    assert listed == set(behaviors), f"README-only: {listed - set(behaviors)}; code-only: {set(behaviors) - listed}"
