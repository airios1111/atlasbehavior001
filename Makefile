PY ?= python3
VENV ?= .venv
BIN := $(VENV)/bin

.PHONY: setup atlas-sync validate test replay build coverage schema fixtures docs lint clean all ocsf-fixtures ocsf-docs ocsf-check verify-branch2

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
	$(BIN)/python -c "import json; from abm.telemetry import AgentSpan; print(json.dumps(AgentSpan.model_json_schema(), indent=2))" > schemas/agent-span.schema.json

fixtures:
	$(BIN)/python scripts/gen_fixtures.py
	$(BIN)/python scripts/gen_otel_fixtures.py
	$(BIN)/python examples/tutorial/gen_fixtures.py

docs:
	$(BIN)/pip install -q -e ".[docs]"
	$(BIN)/python scripts/gen_code_guide.py

lint:
	$(BIN)/ruff check src tests

ocsf-fixtures:
	$(BIN)/python scripts/gen_ocsf_fixtures.py

ocsf-docs:
	$(BIN)/python scripts/gen_ocsf_mapping_doc.py

ocsf-check:
	$(BIN)/python scripts/ocsf_check_upstream.py

verify-branch2:
	$(BIN)/python scripts/verify_branch2.py

clean:
	rm -rf dist/* reports/* .pytest_cache build *.egg-info src/*.egg-info

all: validate test build coverage
