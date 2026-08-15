"""Row-level security actually isolates one tenant's portfolio from another's.

The launcher's whole premise is that `launchable_bindings(db, tenant_id=...)`
returns THIS tenant's applications. If that were only true because the service
adds a `WHERE tenant_id = ...`, a single query that forgot the clause would leak
one customer's connected-application inventory — which application vendors they
use, at which URLs — to another. RLS is what makes the isolation a property of
the database rather than of every future query.

Every assertion here runs as `app_user`, the ONLINE tenant role. Running them as
the migration role would prove nothing: `app_admin` has BYPASSRLS, and the
migration also FORCEs RLS specifically because the table OWNER would otherwise
skip its own policy.

Deliberately raw SQL, not the module's service — a service-side filter must not
be able to masquerade as a database policy.
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import Engine, text
from sqlalchemy.exc import DBAPIError

# Every statement is a literal. Building one by string interpolation would need
# a suppression comment for the SQL-injection rule, and a suppressed security
# rule inside a security canary is the wrong artefact to leave behind — the
# table name is not a variable here.
_SET_TENANT = text("SELECT set_config('app.current_tenant', :value, true)")
_SELECT_TENANTS = text("SELECT tenant_id FROM mod_appdir.application_bindings")
_INSERT_BINDING = text(
    "INSERT INTO mod_appdir.application_bindings ("
    " id, tenant_id, application_code, instance_ref,"
    " local_tenant_ref, admin_url, api_audience,"
    " descriptor_version, descriptor_digest, state, source,"
    " reconciliation_status"
    ") VALUES ("
    " :id, :tenant_id, 'sub', 'planted', 'planted',"
    " 'https://attacker.example/admin', 'https://attacker.example',"
    " 1, :digest, 'active', 'customer_attached', 'fresh'"
    ")"
)


def _visible_tenants(engine: Engine, tenant_id: str | None) -> set[str]:
    """Tenant ids of every binding row visible when scoped to `tenant_id`.

    `set_config(..., true)` is TRANSACTION-local. Session-local would survive
    the connection's return to the pool and silently scope the next test.
    """
    with engine.begin() as conn:
        conn.execute(_SET_TENANT, {"value": tenant_id or ""})
        return {str(row[0]) for row in conn.execute(_SELECT_TENANTS)}


def test_row_level_security_is_enabled_and_forced(admin_engine: Engine) -> None:
    """ENABLE alone is not enough.

    Without FORCE the table owner bypasses its own policy — and migrations run
    as the owner, so the table would look protected in the catalog and be wide
    open to anything connecting as that role.
    """
    with admin_engine.connect() as conn:
        enabled, forced = conn.execute(
            text(
                "SELECT relrowsecurity, relforcerowsecurity FROM pg_class "
                "WHERE oid = 'mod_appdir.application_bindings'::regclass"
            )
        ).one()
    assert enabled, "RLS is not enabled on the bindings table"
    assert forced, "RLS is not FORCEd — the table owner bypasses its own policy"


def test_a_tenant_sees_only_its_own_bindings(
    app_engine: Engine, two_tenants: tuple[str, str]
) -> None:
    left, right = two_tenants
    assert _visible_tenants(app_engine, left) == {left}
    assert _visible_tenants(app_engine, right) == {right}


def test_an_unscoped_session_sees_nothing(
    app_engine: Engine, two_tenants: tuple[str, str]
) -> None:
    """Fail CLOSED. With no tenant set, `app_current_tenant_id()` is NULL, the
    policy predicate is NULL, and no row qualifies. A missing tenant context is
    the one situation where returning everything would be catastrophic, so it
    must return nothing."""
    assert _visible_tenants(app_engine, None) == set()


def test_a_garbage_tenant_context_sees_nothing(
    app_engine: Engine, two_tenants: tuple[str, str]
) -> None:
    """`app_current_tenant_id()` swallows an unparseable value into NULL rather
    than raising, so this is the path where a fail-OPEN bug would hide."""
    assert _visible_tenants(app_engine, "not-a-uuid") == set()


def test_a_tenant_cannot_write_a_row_into_another_tenant(
    app_engine: Engine, two_tenants: tuple[str, str]
) -> None:
    """The policy's `WITH CHECK` half.

    Reading is the obvious direction and the wrong one to stop at: a plane that
    could only be read across tenants leaks, but a plane that could be WRITTEN
    across tenants lets one customer plant a tile — an `admin_url` of their
    choosing — in another customer's launcher.
    """
    left, right = two_tenants
    with app_engine.connect() as conn:
        conn.begin()
        conn.execute(_SET_TENANT, {"value": left})
        with pytest.raises(DBAPIError):
            conn.execute(
                _INSERT_BINDING,
                {
                    "id": str(uuid.uuid4()),
                    "tenant_id": right,
                    "digest": "sha256:" + ("1" * 64),
                },
            )
        conn.rollback()


def test_the_bindings_table_holds_no_authorization_column(
    admin_engine: Engine,
) -> None:
    """ADR-0021 §3, checked against the live catalog rather than the source.

    Directory visibility is not authorization. A directory that acquires a
    person, member, role, grant or permission column has become an access
    control list that no target application agreed to — and the target
    application is the only writer of its own effective role grants.
    """
    with admin_engine.connect() as conn:
        columns = {
            row[0]
            for row in conn.execute(
                text(
                    "SELECT column_name FROM information_schema.columns "
                    "WHERE table_schema = 'mod_appdir' "
                    "AND table_name = 'application_bindings'"
                )
            )
        }
    forbidden = ("person", "party", "member", "user", "role", "grant", "permission")
    offenders = sorted(
        column for column in columns if any(word in column for word in forbidden)
    )
    assert not offenders, f"the directory grew an authorization column: {offenders}"
