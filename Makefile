# Everything by config: every value is an overridable knob with a documented
# default (`?=`), so nothing environment-specific is hardcoded.
PYTHON ?= poetry run
HOST ?= 127.0.0.1
PORT ?= 8100
SRC ?= src/dotmac_workspace

.DEFAULT_GOAL := help

.PHONY: help check lint format type-check test dev migrate

help: ## List targets
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'

lint: ## Ruff lint
	$(PYTHON) ruff check .

format: ## Ruff format
	$(PYTHON) ruff format .

type-check: ## mypy
	$(PYTHON) mypy $(SRC)

check: lint type-check ## Lint + types + format check
	$(PYTHON) ruff format --check .

test: ## pytest
	$(PYTHON) pytest

dev: ## Run the development server
	$(PYTHON) uvicorn dotmac_workspace.main:app --reload --host $(HOST) --port $(PORT)

migrate: ## Compose all three lineages and upgrade
	$(PYTHON) python -c "from alembic import command; from dotmac_workspace.migrations import make_alembic_config; import os; command.upgrade(make_alembic_config(os.environ['MIGRATION_DATABASE_URL']), 'heads')"
