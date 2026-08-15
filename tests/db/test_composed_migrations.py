"""Three separately-owned lineages compose into one graph, against a real database.

Nothing in this repository had ever run a migration — B4 said so plainly. A
composition is not provable statically: `version_locations` can name three
directories that never resolve into one coherent graph, and a logical
prerequisite binding is a string in a Python file that can name a revision which
was stamped rather than run.

So this module asserts against the database that has actually been upgraded:

1. every head of the composed graph is recorded in `alembic_version`;
2. the directory module's lineage really did depend on the revision THIS
   assembly bound it to, rather than on a foreign revision it named itself; and
3. the effects the binding claimed are present in the catalog.

Point 3 is the one that catches a lie. `require_prerequisites` already refuses
to run `ad_0001`'s DDL against a database missing the effects, so reaching this
assertion at all is most of the proof — but asserting the catalog directly means
the evidence does not depend on that verifier having been called.
"""

from __future__ import annotations

import os

from alembic.script import ScriptDirectory
from sqlalchemy import Engine, text

from dotmac_workspace.migration_bindings import ASSEMBLY_PREREQUISITE_BINDINGS
from dotmac_workspace.migrations import make_alembic_config

# Named literally rather than imported from `conftest`: pytest imports a test
# module as a TOP-LEVEL module when its directory has no `__init__.py`, so a
# relative import would fail at collection. The same name is documented in
# `tests/db/conftest.py`.
ADMIN_URL_VAR = "TEST_MIGRATION_DATABASE_URL"


def _script() -> ScriptDirectory:
    """The composed graph, built exactly as `make migrate` builds it.

    Read from the environment rather than from `Engine.url`, which renders its
    password as `***` — a masked URL would silently configure a different
    database than the one under test.
    """
    return ScriptDirectory.from_config(make_alembic_config(os.environ[ADMIN_URL_VAR]))


def _applied(admin_engine: Engine) -> set[str]:
    with admin_engine.connect() as conn:
        return {
            row[0]
            for row in conn.execute(text("SELECT version_num FROM alembic_version"))
        }


def test_every_composed_head_is_actually_applied(admin_engine: Engine) -> None:
    """`upgrade heads` on a composed graph must leave NO head behind.

    A single missing head is the shape of the failure this whole indirection
    exists to prevent: a lineage that is listed, loaded, and never run, so the
    application boots against a database missing one module's tables.
    """
    heads = set(_script().get_heads())
    applied = _applied(admin_engine)
    assert heads, "the composed graph has no heads at all"
    assert heads <= applied, f"composed heads not applied: {sorted(heads - applied)}"


def test_the_directory_lineage_ordered_on_the_revision_this_assembly_bound() -> None:
    """The module declares EFFECTS; the assembly names the revision.

    `ad_0001` carries `requires=("tenant_scope_catalog.v1",
    "module_database_roles.v1")` and no foreign revision id. The physical edge
    is resolved from `dotmac_workspace.migration_bindings` — so this asserts
    that the resolved edge is the one this repository chose, which is the whole
    difference between a module that installs into ERP and one that does not.
    """
    revision = _script().get_revision("ad_0001_application_bindings")
    declared = revision.dependencies or ()
    if isinstance(declared, str):  # Alembic scalarizes a single-element tuple
        declared = (declared,)
    bound = {binding.provider_revision for binding in ASSEMBLY_PREREQUISITE_BINDINGS}
    assert set(declared) == bound


def test_the_bound_effects_are_present_in_the_catalog(admin_engine: Engine) -> None:
    """`tenant_scope_catalog.v1` and `module_database_roles.v1`, observed.

    A binding that named a stamped revision would satisfy the order canary and
    fail here, because stamping writes no columns and creates no roles.
    """
    with admin_engine.connect() as conn:
        assert conn.execute(text("SELECT to_regclass('public.tenants')")).scalar()
        assert conn.execute(
            text("SELECT to_regprocedure('public.app_current_tenant_id()')")
        ).scalar()
        roles = {
            row[0]
            for row in conn.execute(
                text(
                    "SELECT rolname FROM pg_roles WHERE rolname IN "
                    "('app_admin', 'app_user', 'platform_api')"
                )
            )
        }
    assert roles == {"app_admin", "app_user", "platform_api"}


def test_the_directory_module_built_its_own_namespace(admin_engine: Engine) -> None:
    """`mod_appdir`, and the one table the manifest declares — no more.

    A module owns a schema; the composed gate rejects a migration creating
    anything outside its declared `tables`. This is the live half of that.
    """
    with admin_engine.connect() as conn:
        tables = {
            row[0]
            for row in conn.execute(
                text("SELECT tablename FROM pg_tables WHERE schemaname = 'mod_appdir'")
            )
        }
    assert tables == {"application_bindings"}
