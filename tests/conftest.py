from pathlib import Path

import pytest

from abm.catalog import AtlasCatalog
from abm.loader import load_behaviors

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="session")
def root() -> Path:
    return ROOT


@pytest.fixture(scope="session")
def catalog() -> AtlasCatalog:
    return AtlasCatalog.load(ROOT / "atlas" / "catalog.yaml")


@pytest.fixture(scope="session")
def behaviors():
    res = load_behaviors(ROOT / "behaviors")
    assert not res.errors, res.errors
    return res.by_id()
