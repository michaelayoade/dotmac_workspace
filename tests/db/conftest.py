"""Fixtures for the tests that need a real, migrated PostgreSQL.

Everything else under `tests/` is static: structure, refusals, AST properties.
The two things in this directory cannot be proven that way at all —

- that three separately-owned migration lineages actually COMPOSE into one graph
  in the right order against a real database, and
- that row-level security actually isolates one tenant's bindings from another's

— because both are properties of PostgreSQL, not of Python. Nothing here runs in
the ordinary suite (`make test` ignores this directory); it runs in the
`postgres` CI job, after `make test-db-up`.

**Missing URLs are an error, not a skip.** A canary that skips itself when its
database is absent turns a green job into no evidence at all, which is exactly
the failure ADR-0018 names: the region is unmonitored rather than exempt.
"""

from __future__ import annotations

import os
import uuid
from collections.abc import Iterator

import pytest
from dotmac_application_directory import (
    BindingSource,
    BindingState,
    ReconciliationStatus,
)
from sqlalchemy import Engine, create_engine, text

#: The migration/superuser role — RLS-bypassing, used ONLY to arrange fixtures.
ADMIN_URL_VAR = "TEST_MIGRATION_DATABASE_URL"
#: The ONLINE tenant role. Every isolation assertion is made through this one,
#: because `app_admin` bypasses RLS and would prove nothing at all.
APP_URL_VAR = "TEST_DATABASE_URL"

_DIGEST = "sha256:" + ("0" * 64)


def _url(variable: str) -> str:
    value = os.environ.get(variable, "")
    if not value:
        raise RuntimeError(
            f"{variable} is unset. tests/db needs a real migrated PostgreSQL — "
            "run `make test-db-up && make test-db`. These tests must never skip "
            "themselves: a canary that skips is a canary that proves nothing "
            "while the job goes green."
        )
    return value


@pytest.fixture(scope="session")
def admin_engine() -> Iterator[Engine]:
    """RLS-bypassing connection, for arranging and inspecting only."""
    engine = create_engine(_url(ADMIN_URL_VAR), future=True)
    yield engine
    engine.dispose()


@pytest.fixture(scope="session")
def app_engine() -> Iterator[Engine]:
    """The online tenant role — the one every isolation assertion runs as."""
    engine = create_engine(_url(APP_URL_VAR), future=True)
    yield engine
    engine.dispose()


@pytest.fixture
def two_tenants(admin_engine: Engine) -> Iterator[tuple[str, str]]:
    """Two tenants, one launchable binding each, cleaned up afterwards.

    Arranged with raw SQL rather than through the module's service on purpose:
    what is under test is the DATABASE's isolation, and going through the same
    ORM session the application uses would let a service-side filter masquerade
    as an RLS policy. The rows are placed by a role that bypasses RLS, so
    nothing about the arrangement can be doing the isolating.

    The lifecycle values come from the module's own enums, so a renamed member
    breaks this fixture loudly instead of quietly writing a row the application
    would never consider launchable.
    """
    left, right = str(uuid.uuid4()), str(uuid.uuid4())
    with admin_engine.begin() as conn:
        for index, tenant_id in enumerate((left, right)):
            conn.execute(
                text(
                    "INSERT INTO public.tenants (id, slug, name) "
                    "VALUES (:id, :slug, :name)"
                ),
                {
                    "id": tenant_id,
                    "slug": f"rls-canary-{index}-{tenant_id[:8]}",
                    "name": f"RLS canary {index}",
                },
            )
            conn.execute(
                text(
                    "INSERT INTO mod_appdir.application_bindings ("
                    " id, tenant_id, application_code, instance_ref,"
                    " local_tenant_ref, admin_url, api_audience,"
                    " descriptor_version, descriptor_digest, state, source,"
                    " reconciliation_status"
                    ") VALUES ("
                    " :id, :tenant_id, :code, :instance, :local_ref, :admin_url,"
                    " :audience, 1, :digest, :state, :source, :reconciliation"
                    ")"
                ),
                {
                    "id": str(uuid.uuid4()),
                    "tenant_id": tenant_id,
                    "code": "sub",
                    "instance": f"sub-{index}",
                    "local_ref": f"local-{index}",
                    "admin_url": f"https://sub-{index}.example.net/admin",
                    "audience": f"https://sub-{index}.example.net",
                    "digest": _DIGEST,
                    "state": BindingState.ACTIVE.value,
                    "source": BindingSource.CUSTOMER_ATTACHED.value,
                    "reconciliation": ReconciliationStatus.FRESH.value,
                },
            )
    yield left, right
    with admin_engine.begin() as conn:
        # `ON DELETE CASCADE` from the binding's tenant FK removes the bindings.
        conn.execute(
            text("DELETE FROM public.tenants WHERE id IN (:left, :right)"),
            {"left": left, "right": right},
        )
