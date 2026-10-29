import json

import yaml

from abm.catalog import AtlasCatalog
from abm.compilers import TARGETS
from abm.compilers.sigma import rule_id
from abm.coverage import compute, gaps, navigator_layer
from abm.loader import load_behaviors
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
    assert cov["AML.T0040"].score == 0       # precondition-only refs do not count
    assert all(g.score == 0 for g in gaps(cov))


def test_navigator_layer(behaviors, catalog, root):
    layer = navigator_layer(compute(list(behaviors.values()), catalog, root), catalog)
    json.dumps(layer)
    ids = {t["techniqueID"] for t in layer["techniques"]}
    assert "AML.T0051.000" in ids and "AML.T0040" not in ids


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
    listed = set(re.findall(r"^\| (BHV-[A-Z]+-\d{3}) \|", table, flags=re.M))
    assert listed == set(behaviors), f"README-only: {listed - set(behaviors)}; code-only: {set(behaviors) - listed}"
