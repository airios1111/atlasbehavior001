PY ?= python3
VENV ?= .venv
BIN := $(VENV)/bin

.PHONY: setup atlas-sync validate test replay build coverage schema fixtures lint clean all

setup:
	$(PY) -m venv $(VENV)
	$(BIN)/pip install -q -U pip
	$(BIN)/pip install -q -e ".[dev]"

atlas-sync:
	$(BIN)/abm atlas-sync

validate:
	$(BIN)/abm validate --run-tests

test:
	$(BIN)/pytest -q

replay:
	$(BIN)/abm test

build:
	$(BIN)/abm compile --target all

coverage:
	$(BIN)/abm coverage

schema:
	$(BIN)/python -c "import json; from abm.models import Behavior; print(json.dumps(Behavior.model_json_schema(), indent=2))" > schemas/behavior.schema.json

fixtures:
	$(BIN)/python scripts/gen_fixtures.py

lint:
	$(BIN)/ruff check src tests

clean:
	rm -rf dist/* reports/* .pytest_cache build *.egg-info src/*.egg-info

all: validate test build coverage
