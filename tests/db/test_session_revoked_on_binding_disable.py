"""Disable a binding, and the session it issued stops working.

The adoption proof for kernel a67. Not a restatement of the kernel's own canary
— that one asserts `revoked_at` is set on the right rows. This one asserts the
consequence the Workspace actually cares about: **a member who was signed in is
no longer signed in**, judged by the same code path that guards every page.

    login  ->  session issued, provenance stamped
    disable ->  kernel revokes it
    request ->  refused

## Why it goes through `authenticate_request` rather than reading a column

Checking `revoked_at IS NOT NULL` would prove the kernel wrote a value. It would
not prove the Workspace HONOURS it — a guard that read sessions without checking
revocation would leave that assertion green while every disabled member kept
browsing. So the last step asks the real validator, which is the one both the
portal (`require_workspace_auth`) and any bearer caller go through.

## Why it needs a real database

`external_identity_binding_id` is a kernel column with a composite FK carrying
`party_id`; the revocation is an `UPDATE` under a `SELECT … FOR UPDATE`; and the
whole thing sits under an RLS policy. None of that exists in the unit lane —
SQLAlchemy's SQLite compiler even drops `FOR UPDATE` silently.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterator

import pytest
from dotmac_kernel.deps import authenticate_request
from dotmac_kernel.external_identity import (
    bind_external_identity,
    disable_external_identity_binding,
)
from dotmac_kernel.models import Party, PartyType, Tenant
from sqlalchemy import Engine, text
from sqlalchemy.orm import Session, sessionmaker

from dotmac_workspace.identity import session as workspace_session

PROVIDER = "primary"
ISSUER = "https://idp.dotmac.io/realms/dotmac"


@pytest.fixture
def tenant_session(app_engine: Engine, admin_engine: Engine) -> Iterator[Session]:
    """One tenant, and a session bound to it through `app.current_tenant`.

    The ONLINE role, not the admin one: this canary is about what the running
    application can see and do, and arranging it as a role that bypasses RLS
    would let the arrangement do the isolating.
    """
    tenant_id = uuid.uuid4()
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO public.tenants (id, slug, name) "
                "VALUES (:id, :slug, :name)"
            ),
            {
                "id": str(tenant_id),
                "slug": f"a67-canary-{str(tenant_id)[:8]}",
                "name": "a67 provenance canary",
            },
        )

    factory = sessionmaker(bind=app_engine, autocommit=False, autoflush=False)
    db = factory()
    db.execute(
        text("SELECT set_config('app.current_tenant', :t, true)"),
        {"t": str(tenant_id)},
    )
    db.info["tenant_id"] = tenant_id
    try:
        yield db
    finally:
        db.rollback()
        db.close()
        with admin_engine.begin() as conn:
            conn.execute(
                text("DELETE FROM public.tenants WHERE id = :id"),
                {"id": str(tenant_id)},
            )


class _Request:
    """The two attributes `authenticate_request` reads. A real `Request` would
    drag in an ASGI scope this canary has no use for."""

    def __init__(self, tenant: Tenant) -> None:
        self.state = type("S", (), {"tenant": tenant})()
        self.headers: dict[str, str] = {}
        self.cookies: dict[str, str] = {}


def _member(db: Session, tenant: Tenant) -> Party:
    party = Party(
        tenant_id=tenant.id,
        party_type=PartyType.person,
        display_name="A67 Canary",
        email=f"a67-{uuid.uuid4()}@example.com",
        is_active=True,
    )
    db.add(party)
    db.flush()
    return party


def test_disabling_the_binding_refuses_the_session_it_issued(
    tenant_session: Session,
) -> None:
    """The whole point of a67, end to end, through this assembly's own code."""
    db = tenant_session
    tenant = db.get(Tenant, db.info["tenant_id"])
    assert tenant is not None

    party = _member(db, tenant)
    subject = f"sub-{uuid.uuid4()}"
    binding = bind_external_identity(
        db,
        tenant=tenant,
        party=party,
        provider_binding=PROVIDER,
        issuer=ISSUER,
        subject=subject,
        bound_by="canary@dotmac.io",
        reason="a67 adoption proof",
    )
    db.flush()

    # 1. LOGIN — the session this assembly issues, stamped with the binding the
    #    finalizer identified.
    auth_session, token = workspace_session.issue(
        db, tenant=tenant, party=party, binding_id=binding.id
    )
    db.flush()
    assert auth_session.external_identity_binding_id == binding.id, (
        "the session was issued without provenance — selective revocation has "
        "nothing to select on"
    )

    request = _Request(tenant)
    signed_in = authenticate_request(request, db, token=token)
    assert signed_in.id == party.id, "the freshly issued session did not work"

    # 2. DISABLE — one kernel call. Not disable-then-revoke; the contract says
    #    those must not be two things a caller can do half of.
    disable_external_identity_binding(db, tenant=tenant, binding_id=binding.id)
    db.flush()

    # 3. REFUSED — asked of the real validator, not of a column.
    #
    # `authenticate_request` RETURNS `Party | None`; it does not raise. Asserting
    # an exception here would have passed against a validator that returned a
    # perfectly good party, which is the opposite of what this canary is for.
    assert authenticate_request(request, db, token=token) is None, (
        "the session issued from a now-disabled binding still authenticates — "
        "either the kernel did not revoke it or this assembly does not honour "
        "revocation, and both look identical from a member's browser"
    )


def test_disabling_one_binding_leaves_another_members_session_working(
    tenant_session: Session,
) -> None:
    """Selective, judged the same way.

    The kernel proves it does not revoke the wrong ROWS. This proves the
    Workspace does not sign out the wrong PERSON — the failure an operator would
    actually report, and the one a `WHERE` clause off by one column produces.
    """
    db = tenant_session
    tenant = db.get(Tenant, db.info["tenant_id"])
    assert tenant is not None

    alice, bob = _member(db, tenant), _member(db, tenant)
    bindings = {}
    tokens = {}
    for name, party in (("alice", alice), ("bob", bob)):
        bindings[name] = bind_external_identity(
            db,
            tenant=tenant,
            party=party,
            provider_binding=PROVIDER,
            issuer=ISSUER,
            subject=f"sub-{name}-{uuid.uuid4()}",
            bound_by="canary@dotmac.io",
            reason="a67 adoption proof",
        )
        db.flush()
        _, tokens[name] = workspace_session.issue(
            db, tenant=tenant, party=party, binding_id=bindings[name].id
        )
    db.flush()

    request = _Request(tenant)
    disable_external_identity_binding(
        db, tenant=tenant, binding_id=bindings["alice"].id
    )
    db.flush()

    assert authenticate_request(request, db, token=tokens["alice"]) is None

    still_in = authenticate_request(request, db, token=tokens["bob"])
    assert still_in.id == bob.id, (
        "disabling Alice's binding signed Bob out — the revocation is not "
        "selective, and an operator disabling one member would log out the "
        "whole tenant"
    )
