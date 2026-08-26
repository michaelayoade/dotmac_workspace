# Everything by config: every value is an overridable knob with a documented
# default (`?=`), so nothing environment-specific is hardcoded.
PYTHON ?= poetry run
HOST ?= 127.0.0.1
PORT ?= 8100
SRC ?= src/dotmac_workspace

# The disposable test database. Same knobs the compose file reads, so a CI run
# and a laptop run configure ONE thing. The Workspace database is its own
# (ADR-0021 §1): no product DSN appears here and nothing connects to one.
TEST_DB_HOST ?= localhost
TEST_DB_PORT ?= 5434
TEST_DB_NAME ?= workspace_test
TEST_DB_ADMIN_USER ?= postgres
TEST_DB_ADMIN_PASSWORD ?= postgres
# The ONLINE tenant role, created with LOGIN and no password by kernel `0001`.
# The test compose uses trust auth, so the password value is irrelevant there.
TEST_DB_USER ?= app_user
TEST_DB_PASSWORD ?= app_user

TEST_ADMIN_DSN = postgresql+psycopg://$(TEST_DB_ADMIN_USER):$(TEST_DB_ADMIN_PASSWORD)@$(TEST_DB_HOST):$(TEST_DB_PORT)/$(TEST_DB_NAME)
TEST_APP_DSN = postgresql+psycopg://$(TEST_DB_USER):$(TEST_DB_PASSWORD)@$(TEST_DB_HOST):$(TEST_DB_PORT)/$(TEST_DB_NAME)

# Alembic's graph commands (`heads`, `history`, `show`) never run `env.py`, so
# they see neither the composed `version_locations` nor the prerequisite
# bindings it installs. `migrate-graph` therefore goes through the same
# `make_alembic_config` as `migrate` — which sets both — rather than through the
# raw `alembic` CLI, whose `alembic.ini` deliberately names no lineage at all.
# Inspecting the graph needs no database, so the URL is a placeholder knob.
GRAPH_DATABASE_URL ?= postgresql+psycopg://unused:unused@127.0.0.1:1/unused

# The nginx site in front of this plane. `deploy/nginx/workspace.conf.template`
# is the SOURCE; the file under /etc/nginx on the host is a rendered artifact.
# envsubst is restricted to these two names on purpose — unrestricted it would
# also substitute nginx's own $host/$scheme/$remote_addr and emit a config
# that proxies with empty headers.
NGINX_PUBLIC_HOST ?= workspace.dotmac.io
NGINX_UPSTREAM ?= http://127.0.0.1:8000
NGINX_TEMPLATE ?= deploy/nginx/workspace.conf.template
NGINX_SSH ?= root@$(NGINX_PUBLIC_HOST)
NGINX_SITE ?= /etc/nginx/sites-available/$(NGINX_PUBLIC_HOST)

.DEFAULT_GOAL := help

.PHONY: help check lint format type-check test test-db dev migrate migrate-graph \
	test-db-up test-db-down from-wheel-boot nginx-render nginx-diff

help: ## List targets
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'

lint: ## Ruff lint
	$(PYTHON) ruff check .

format: ## Ruff format
	$(PYTHON) ruff format .

type-check: ## mypy
	$(PYTHON) mypy $(SRC)

check: lint type-check ## Lint + types + format check
	$(PYTHON) ruff format --check .

test: ## Static + unit tests (no database)
	$(PYTHON) pytest --ignore=tests/db

test-db: ## Composed-migration + RLS canaries (needs test-db-up)
	TEST_DATABASE_URL=$(TEST_APP_DSN) \
	TEST_MIGRATION_DATABASE_URL=$(TEST_ADMIN_DSN) \
	DATABASE_URL=$(TEST_APP_DSN) \
	$(PYTHON) pytest tests/db

test-db-up: ## Start the disposable test Postgres and apply all three lineages
	TEST_DB_PORT=$(TEST_DB_PORT) TEST_DB_NAME=$(TEST_DB_NAME) \
	TEST_DB_ADMIN_USER=$(TEST_DB_ADMIN_USER) TEST_DB_ADMIN_PASSWORD=$(TEST_DB_ADMIN_PASSWORD) \
	docker compose -f docker-compose.test.yml up -d --wait
	MIGRATION_DATABASE_URL=$(TEST_ADMIN_DSN) DATABASE_URL=$(TEST_ADMIN_DSN) $(MAKE) migrate

test-db-down: ## Stop and erase the test Postgres
	TEST_DB_PORT=$(TEST_DB_PORT) TEST_DB_NAME=$(TEST_DB_NAME) \
	TEST_DB_ADMIN_USER=$(TEST_DB_ADMIN_USER) TEST_DB_ADMIN_PASSWORD=$(TEST_DB_ADMIN_PASSWORD) \
	docker compose -f docker-compose.test.yml down -v

from-wheel-boot: ## Prove the app boots from built wheels, not this checkout
	bash scripts/from_wheel_boot.sh

dev: ## Run the development server
	$(PYTHON) uvicorn dotmac_workspace.main:app --reload --host $(HOST) --port $(PORT)

migrate: ## Compose all three lineages and upgrade
	$(PYTHON) python -c "from alembic import command; from dotmac_workspace.migrations import make_alembic_config; import os; command.upgrade(make_alembic_config(os.environ['MIGRATION_DATABASE_URL']), 'heads')"

migrate-graph: ## Show the composed revision graph (all three lineages)
	$(PYTHON) python -c "from alembic import command; from dotmac_workspace.migrations import make_alembic_config; import os; command.history(make_alembic_config(os.environ.get('MIGRATION_DATABASE_URL') or '$(GRAPH_DATABASE_URL)'))"

nginx-render: ## Render the nginx vhost from its tracked template
	@WORKSPACE_PUBLIC_HOST='$(NGINX_PUBLIC_HOST)' WORKSPACE_UPSTREAM='$(NGINX_UPSTREAM)' \
		envsubst '$${WORKSPACE_PUBLIC_HOST} $${WORKSPACE_UPSTREAM}' < $(NGINX_TEMPLATE)

nginx-diff: ## Fail if the deployed vhost has drifted from the tracked template
	@$(MAKE) --no-print-directory nginx-render > /tmp/workspace-nginx-rendered.conf
	@ssh -o BatchMode=yes $(NGINX_SSH) 'cat $(NGINX_SITE)' > /tmp/workspace-nginx-deployed.conf
	@if diff -u /tmp/workspace-nginx-rendered.conf /tmp/workspace-nginx-deployed.conf; then \
		echo "nginx vhost matches $(NGINX_TEMPLATE)"; \
	else \
		echo "DRIFT: the deployed vhost differs from the tracked template" >&2; exit 1; \
	fi
