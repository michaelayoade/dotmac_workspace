"""The operator routes, driven as HTTP. Not their pieces — the routes.

## Why this file exists

Every mutating operator control shipped broken and CI passed 4/4. The unit
suite checked the right things and checked them well — that each route carries
the right permission stamp, that the stranding arithmetic is correct — but it
reached those things through fakes, so nothing ever sent a request. Starlette's
`request.form()` asserts on `python-multipart` being installed, that dependency
was missing, and every `hx-post` on both screens answered 500 in production
while the test suite stayed green.

A guard that never exercises the transport cannot see a transport failure. So
these drive the real ASGI app with a real client: real routing, real dependency
resolution, real body parsing.

The database and the authenticated party are substituted — this is the DB-free
lane and tenancy correctness belongs to the Postgres canaries — but everything
between the socket and the service call is genuine, which is exactly the part
that was untested.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any
from uuid import uuid4

import pytest
from dotmac_kernel.deps import get_db
from dotmac_kernel.templating import compose_templates, install_stylesheets
from fastapi import FastAPI
from fastapi.testclient import TestClient

from dotmac_workspace.assembly import build_spec
from dotmac_workspace.operator import guard, service, web

TENANT = SimpleNamespace(id=uuid4(), slug="acme")
OPERATOR = SimpleNamespace(id=uuid4(), email="op@example.net", display_name="Op")


@pytest.fixture
def client(monkeypatch: pytest.MonkeyPatch) -> TestClient:
    """The real router, mounted on a bare app with the guards satisfied.

    `require_tenant` and the permission guards are overridden because what is
    under test is the ROUTE — its methods, its body parsing, its delegation —
    not the authorization those guards perform, which
    `test_operator_surface.py` pins directly and in more detail.
    """
    spec = build_spec()
    compose_templates(assembly_dir=spec.assembly_template_dir)
    install_stylesheets(spec.stylesheets)
    app = FastAPI()

    @app.middleware("http")
    async def _attach_tenant(request: Any, call_next: Any) -> Any:
        request.state.tenant = TENANT
        return await call_next(request)

    app.include_router(web.router)
    for dependency in (
        guard.require_members_read,
        guard.require_members_manage,
        guard.require_identity_read,
        guard.require_identity_manage,
    ):
        app.dependency_overrides[dependency] = lambda: OPERATOR
    app.dependency_overrides[get_db] = lambda: object()

    monkeypatch.setattr(service, "list_members", lambda db, *, tenant: [])
    return TestClient(app)


def test_the_members_screen_renders(client: TestClient) -> None:
    response = client.get(web.MEMBERS_PATH)
    assert response.status_code == 200
    assert "Add a member" in response.text


def test_the_identity_screen_renders(client: TestClient) -> None:
    response = client.get(web.IDENTITY_PATH)
    assert response.status_code == 200


def test_adding_a_member_parses_its_form_body(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The exact failure that reached production.

    An `hx-post` sends `application/x-www-form-urlencoded`. If the app cannot
    parse that, this answers 500 — which is what every operator control did
    while the suite was green.
    """
    seen: dict[str, str] = {}

    def _add(
        db: Any,
        *,
        tenant: Any,
        email: str,
        first_name: str,
        last_name: str,
        **kw: Any,
    ):
        seen.update(email=email, first_name=first_name, last_name=last_name)
        return SimpleNamespace(id=uuid4())

    monkeypatch.setattr(service, "add_member", _add)
    response = client.post(
        web.MEMBERS_PATH,
        data={"email": "a@b.c", "first_name": "Ada", "last_name": "Lovelace"},
    )
    assert response.status_code == 200, response.text[:200]
    assert seen == {"email": "a@b.c", "first_name": "Ada", "last_name": "Lovelace"}


def test_adding_a_member_without_the_required_fields_says_so(
    client: TestClient,
) -> None:
    response = client.post(web.MEMBERS_PATH, data={"email": "a@b.c"})
    assert response.status_code == 200
    assert "required" in response.text


def test_revoking_reads_the_role_from_the_body(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: dict[str, Any] = {}

    def _revoke(db: Any, *, tenant: Any, party_id: Any, role_slug: str) -> None:
        seen.update(party_id=party_id, role_slug=role_slug)

    monkeypatch.setattr(service, "revoke_role", _revoke)
    party_id = uuid4()
    response = client.post(
        f"{web.MEMBERS_PATH}/{party_id}/revoke", data={"role_slug": "admin"}
    )
    assert response.status_code == 200, response.text[:200]
    assert seen == {"party_id": party_id, "role_slug": "admin"}


def test_a_refused_revocation_is_shown_to_the_operator(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A safety refusal exists to be READ.

    htmx does not swap a non-2xx response, so answering 409 here would leave
    the operator looking at an unchanged screen with no explanation.
    """

    def _refuse(*args: Any, **kwargs: Any) -> None:
        raise service.ConflictError("Refusing: this is the last administrator.")

    monkeypatch.setattr(service, "revoke_role", _refuse)
    response = client.post(
        f"{web.MEMBERS_PATH}/{uuid4()}/revoke", data={"role_slug": "admin"}
    )
    assert response.status_code == 200
    assert "last administrator" in response.text
    assert 'role="alert"' in response.text


def test_binding_takes_bound_by_from_the_session_not_the_body(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The evidence rule, proven over the wire.

    `test_operator_surface.py` asserts the handler never READS `bound_by` from
    the request. This asserts the other half: what actually reaches the service
    is the authenticated operator, even when the browser tries to supply
    somebody else's name.
    """
    seen: dict[str, Any] = {}

    def _bind(db: Any, **kwargs: Any):
        seen.update(kwargs)
        return SimpleNamespace(id=uuid4())

    monkeypatch.setattr(service, "bind_member", _bind)
    monkeypatch.setattr(
        web,
        "provider_or_none",
        lambda: SimpleNamespace(
            issuer="https://idp.example.net", provider_binding="primary"
        ),
    )
    response = client.post(
        f"{web.IDENTITY_PATH}/bind",
        data={
            "email": "a@b.c",
            "subject": "sub-1",
            "reason": "ticket 4417",
            "bound_by": "somebody-else@evil.example",
        },
    )
    assert response.status_code == 200, response.text[:200]
    assert seen["bound_by"] == OPERATOR.email, (
        f"bound_by reached the service as {seen['bound_by']!r} — the browser "
        "supplied a value and it was believed"
    )


def test_binding_without_a_reason_is_refused(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The reason is evidence, not a nicety."""
    monkeypatch.setattr(
        web,
        "provider_or_none",
        lambda: SimpleNamespace(
            issuer="https://idp.example.net", provider_binding="primary"
        ),
    )
    called = False

    def _bind(*args: Any, **kwargs: Any):
        nonlocal called
        called = True

    monkeypatch.setattr(service, "bind_member", _bind)
    response = client.post(
        f"{web.IDENTITY_PATH}/bind", data={"email": "a@b.c", "subject": "sub-1"}
    )
    assert response.status_code == 200
    assert not called, "a binding was attempted with no recorded reason"
    assert "reason" in response.text.lower()


def test_disabling_a_binding_reaches_the_service(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: dict[str, Any] = {}

    def _disable(db: Any, *, tenant: Any, binding_id: Any):
        seen["binding_id"] = binding_id
        return SimpleNamespace(id=binding_id)

    monkeypatch.setattr(service, "disable_binding_for", _disable)
    monkeypatch.setattr(web, "provider_or_none", lambda: None)
    binding_id = uuid4()
    response = client.post(f"{web.IDENTITY_PATH}/{binding_id}/disable")
    assert response.status_code == 200, response.text[:200]
    assert seen == {"binding_id": binding_id}


def test_every_mutating_route_answers_a_urlencoded_body(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The sweep, so a NEW mutating route cannot repeat this failure quietly.

    Each route is driven with an empty urlencoded body. What is asserted is
    only that the request was parsed and handled — never a 500, which is what a
    body the application cannot read produces.

    The domain calls are stubbed because this is a TRANSPORT check: with the
    real service and a stub session it would fail on `db.scalars`, which is a
    true statement about the fake database and says nothing about whether the
    request body was readable. Keeping the two apart is what lets a failure
    here mean exactly one thing.
    """
    for name in ("add_member", "revoke_role", "bind_member", "disable_binding_for"):
        monkeypatch.setattr(service, name, lambda *a, **k: SimpleNamespace(id=uuid4()))
    monkeypatch.setattr(
        web,
        "provider_or_none",
        lambda: SimpleNamespace(
            issuer="https://idp.example.net", provider_binding="primary"
        ),
    )

    for path in (
        web.MEMBERS_PATH,
        f"{web.MEMBERS_PATH}/{uuid4()}/revoke",
        f"{web.IDENTITY_PATH}/bind",
        f"{web.IDENTITY_PATH}/{uuid4()}/disable",
    ):
        response = client.post(path, data={})
        assert (
            response.status_code != 500
        ), f"POST {path} answered 500 on a urlencoded body: {response.text[:200]}"
