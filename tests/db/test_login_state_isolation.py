"""One tenant's login ceremonies are invisible and unusable to another.

Ceremony state is short-lived, but while it lives it holds a PKCE verifier and
a nonce. A cross-tenant read of that table would let a tenant complete another
tenant's login, so the isolation here is not administrative tidiness — it is
the same property the rest of the estate has, applied to the front door.

Every assertion is made through the ONLINE role (`app_user`). `app_admin` and
the test superuser bypass RLS and would prove nothing at all; they appear below
only to ARRANGE rows, so that nothing about the arrangement can be doing the
isolating.

`set_config('app.current_tenant', …, true)` is TRANSACTION-local, so it is set
inside each transaction under test, and the fixture seeds in its own
short-lived superuser sessions.
"""

from __future__ import annotations

import hashlib
import uuid
from collections.abc import Iterator

import pytest
from sqlalchemy import Engine, text
from sqlalchemy.exc import DBAPIError

TABLE = "public.workspace_login_states"


def _state_hash(state: str) -> str:
    return hashlib.sha256(state.encode("utf-8")).hexdigest()


@pytest.fixture
def two_ceremonies(admin_engine: Engine) -> Iterator[tuple[str, str, str]]:
    """Two tenants, one ceremony each, sharing the SAME state value.

    Sharing the state is the point: it makes the tenant column the only thing
    that can distinguish the rows, so a policy that scoped on the state alone
    would fail here rather than passing by accident.

    Yields `(left_tenant_id, right_tenant_id, shared_state)`.
    """
    left, right = str(uuid.uuid4()), str(uuid.uuid4())
    state = f"shared-{uuid.uuid4()}"
    for index, tenant_id in enumerate((left, right)):
        with admin_engine.begin() as conn:
            conn.execute(
                text(
                    "INSERT INTO public.tenants (id, slug, name) "
                    "VALUES (:id, :slug, :name)"
                ),
                {
                    "id": tenant_id,
                    "slug": f"login-rls-{index}-{tenant_id[:8]}",
                    "name": f"Login RLS canary {index}",
                },
            )
        with admin_engine.begin() as conn:
            conn.execute(
                text(
                    f"INSERT INTO {TABLE} ("
                    " id, tenant_id, state_hash, code_verifier, nonce,"
                    " redirect_uri, return_to, issued_at, provider_binding, expires_at"
                    ") VALUES ("
                    " :id, :tenant_id, :state_hash, :verifier, :nonce,"
                    " :redirect_uri, :return_to, :issued_at, :binding,"
                    " now() + interval '10 minutes'"
                    ")"
                ),
                {
                    "id": str(uuid.uuid4()),
                    "tenant_id": tenant_id,
                    "state_hash": _state_hash(state),
                    "verifier": f"verifier-for-{index}",
                    "nonce": f"nonce-for-{index}",
                    "redirect_uri": "https://ws.example.net/login/callback",
                    "return_to": "/applications",
                    "issued_at": 1_770_000_000,
                    "binding": "primary",
                },
            )
    yield left, right, state
    with admin_engine.begin() as conn:
        conn.execute(
            text("DELETE FROM public.tenants WHERE id IN (:left, :right)"),
            {"left": left, "right": right},
        )


def test_a_tenant_sees_only_its_own_ceremonies(
    app_engine: Engine, two_ceremonies: tuple[str, str, str]
) -> None:
    left, _right, state = two_ceremonies
    with app_engine.connect() as conn, conn.begin():
        conn.execute(
            text("SELECT set_config('app.current_tenant', :tenant_id, true)"),
            {"tenant_id": left},
        )
        rows = conn.execute(text(f"SELECT tenant_id, code_verifier FROM {TABLE}")).all()
    assert [str(row[0]) for row in rows] == [left]
    assert rows[0][1] == "verifier-for-0"


def test_a_tenant_cannot_consume_another_tenants_ceremony(
    app_engine: Engine, admin_engine: Engine, two_ceremonies: tuple[str, str, str]
) -> None:
    """The one that matters.

    Both rows carry the same state value, so only the tenant scope separates
    them. Consuming as the LEFT tenant must take the left row and leave the
    right one untouched — a policy that let it take either would hand one
    tenant another's PKCE verifier.
    """
    left, right, state = two_ceremonies
    with app_engine.connect() as conn, conn.begin():
        conn.execute(
            text("SELECT set_config('app.current_tenant', :tenant_id, true)"),
            {"tenant_id": left},
        )
        conn.execute(text("SET LOCAL statement_timeout = '15s'"))
        row = (
            conn.execute(
                text(
                    f"DELETE FROM {TABLE} "
                    "WHERE tenant_id = :tenant_id AND state_hash = :state_hash "
                    "  AND expires_at > now() "
                    "RETURNING code_verifier"
                ),
                {"tenant_id": left, "state_hash": _state_hash(state)},
            )
            .mappings()
            .first()
        )
    assert row is not None
    assert row["code_verifier"] == "verifier-for-0"

    with admin_engine.connect() as conn:
        survivors = conn.execute(
            text(f"SELECT tenant_id FROM {TABLE} WHERE state_hash = :h"),
            {"h": _state_hash(state)},
        ).all()
    assert [str(item[0]) for item in survivors] == [right]


def test_a_tenant_cannot_delete_across_the_boundary_even_naming_the_id(
    app_engine: Engine, admin_engine: Engine, two_ceremonies: tuple[str, str, str]
) -> None:
    """Naming the other tenant's id explicitly still deletes nothing.

    This is the case that separates a POLICY from an application-side filter: a
    service that merely added `WHERE tenant_id = …` would be defeated by a
    statement that supplied a different one.
    """
    left, right, state = two_ceremonies
    with app_engine.connect() as conn, conn.begin():
        conn.execute(
            text("SELECT set_config('app.current_tenant', :tenant_id, true)"),
            {"tenant_id": left},
        )
        conn.execute(text("SET LOCAL statement_timeout = '15s'"))
        deleted = conn.execute(
            text(f"DELETE FROM {TABLE} WHERE tenant_id = :tenant_id RETURNING id"),
            {"tenant_id": right},
        ).all()
    assert deleted == []

    with admin_engine.connect() as conn:
        still_there = conn.execute(
            text(f"SELECT count(*) FROM {TABLE} WHERE tenant_id = :id"),
            {"id": right},
        ).scalar()
    assert still_there == 1


def test_a_ceremony_cannot_be_written_for_another_tenant(
    app_engine: Engine, two_ceremonies: tuple[str, str, str]
) -> None:
    """`WITH CHECK`, not just `USING`.

    Without it a tenant could INSERT a ceremony carrying another tenant's id —
    a row it could not then see, but which the other tenant's callback could
    consume, with a verifier the writer chose.
    """
    left, right, _state = two_ceremonies
    with pytest.raises(DBAPIError), app_engine.connect() as conn, conn.begin():
        conn.execute(
            text("SELECT set_config('app.current_tenant', :tenant_id, true)"),
            {"tenant_id": left},
        )
        conn.execute(text("SET LOCAL statement_timeout = '15s'"))
        conn.execute(
            text(
                f"INSERT INTO {TABLE} ("
                " id, tenant_id, state_hash, code_verifier, nonce,"
                " redirect_uri, return_to, issued_at, provider_binding, expires_at"
                ") VALUES ("
                " :id, :tenant_id, :state_hash, 'planted', 'planted',"
                " 'https://ws.example.net/login/callback', '/applications',"
                " 1770000000, 'primary', now() + interval '10 minutes'"
                ")"
            ),
            {
                "id": str(uuid.uuid4()),
                "tenant_id": right,
                "state_hash": _state_hash("planted-state"),
            },
        )


def test_row_level_security_is_enabled_and_forced(admin_engine: Engine) -> None:
    """FORCE is the half that is easy to omit and invisible when missing.

    Without it the table OWNER — the role migrations run as — bypasses its own
    policy, and every canary that arranges rows as the owner proves nothing.
    """
    with admin_engine.connect() as conn:
        enabled, forced = conn.execute(
            text(
                "SELECT relrowsecurity, relforcerowsecurity FROM pg_class "
                "WHERE oid = 'public.workspace_login_states'::regclass"
            )
        ).one()
    assert enabled, "RLS is not enabled on the ceremony table"
    assert forced, "RLS is not FORCEd on the ceremony table"


def test_the_online_role_can_read_write_and_delete_but_never_update(
    admin_engine: Engine,
) -> None:
    """Consuming a ceremony is a DELETE; nothing amends one.

    A store whose rows can be edited is one where a verifier can be swapped for
    one the attacker already knows, so the privilege is withheld rather than
    merely unused.
    """
    with admin_engine.connect() as conn:
        granted = {
            row[0]
            for row in conn.execute(
                text(
                    "SELECT privilege_type FROM information_schema.table_privileges "
                    "WHERE table_schema = 'public' "
                    "  AND table_name = 'workspace_login_states' "
                    "  AND grantee = 'app_user'"
                )
            )
        }
    assert {"SELECT", "INSERT", "DELETE"} <= granted
    assert "UPDATE" not in granted, (
        "app_user can UPDATE a login ceremony. Consuming is a DELETE and "
        "nothing amends one; an updatable ceremony is a verifier that can be "
        "swapped."
    )


def test_the_platform_role_has_no_access_to_login_ceremonies(
    admin_engine: Engine,
) -> None:
    """A ceremony is a tenant's, mid-flight. The vendor control plane has no
    business in one, so the grant is absent rather than unused."""
    with admin_engine.connect() as conn:
        granted = {
            row[0]
            for row in conn.execute(
                text(
                    "SELECT privilege_type FROM information_schema.table_privileges "
                    "WHERE table_schema = 'public' "
                    "  AND table_name = 'workspace_login_states' "
                    "  AND grantee = 'platform_api'"
                )
            )
        }
    assert not granted, f"platform_api holds {sorted(granted)} on login ceremonies"
