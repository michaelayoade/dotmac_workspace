"""The operator surface: every route authorized, and the lockout it refuses.

Two properties, and the second is the reason this screen exists at all rather
than being a prettier CLI.

1. **Every operator route depends on a stamped permission guard.** Not "has a
   guard" — has the RIGHT one. A screen that reads members while stamped with
   the binding permission would be enforcing the wrong decision, and `create_app`
   would happily boot it because the code is declared somewhere.

2. **Neither write can strand the tenant.** Revoking the last administrative
   role, or disabling the last usable binding, ends with nobody able to sign in
   and administer — recoverable only from a shell on the application host. The
   CLI is allowed to do that; the browser is not.

No database. `authorize_party` is the kernel's one permission decision and is
substituted, because what is under test is which answer this assembly turns a
`False` into. The stranding tests drive the real service against a fake session
whose only job is to return the rows the service asks for — the arithmetic being
checked is this module's, not SQLAlchemy's.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any
from uuid import UUID, uuid4

import pytest
from dotmac_kernel import deps as kernel_deps
from dotmac_kernel.exceptions import ConflictError
from dotmac_kernel.permissions import PERMISSION_CODE_ATTR

from dotmac_workspace.operator import guard, service, web
from dotmac_workspace.operator.feature import feature

# ── 1. declarations and stamps ──────────────────────────────────────────────


def test_every_declared_permission_is_reachable() -> None:
    """A permission no role can hold is an unreachable screen, not a lockdown."""
    for spec in feature.permissions:
        assert tuple(spec.default_roles), f"{spec.code} is held by no role"


def test_the_manifest_declares_exactly_what_the_guards_enforce() -> None:
    """Both directions.

    A declared code with no consumer is dead vocabulary (ADR-0008). A consumed
    code with no declaration stops the boot — which is better, but is a defect
    found at deploy time rather than here.
    """
    declared = {spec.code for spec in feature.permissions}
    enforced = {
        getattr(g, PERMISSION_CODE_ATTR)
        for g in (
            guard.require_members_read,
            guard.require_members_manage,
            guard.require_identity_read,
            guard.require_identity_manage,
        )
    }
    assert declared == enforced, (
        f"declared-but-unused: {sorted(declared - enforced)}; "
        f"used-but-undeclared: {sorted(enforced - declared)}"
    )


def test_reading_and_managing_are_not_the_same_code() -> None:
    """The split is the design (see guard.py). Collapsing it would force anyone
    who may LOOK at members to also hold the authority to bind an identity."""
    assert guard.MEMBERS_READ != guard.MEMBERS_MANAGE
    assert guard.IDENTITY_READ != guard.IDENTITY_MANAGE
    assert guard.MEMBERS_MANAGE != guard.IDENTITY_MANAGE


def _route(path: str, method: str):
    for route in web.router.routes:
        if getattr(route, "path", None) == path and method in getattr(
            route, "methods", set()
        ):
            return route
    raise AssertionError(f"no {method} route mounted at {path}")


def _dependency_calls(dependant: Any) -> set[Any]:
    found: set[Any] = set()
    pending = list(dependant.dependencies)
    while pending:
        sub = pending.pop()
        if sub.call is not None:
            found.add(sub.call)
        pending.extend(sub.dependencies)
    return found


@pytest.mark.parametrize(
    ("path", "method", "expected"),
    [
        (web.MEMBERS_PATH, "GET", guard.MEMBERS_READ),
        (web.MEMBERS_PATH, "POST", guard.MEMBERS_MANAGE),
        (web.MEMBERS_PATH + "/{party_id}/revoke", "POST", guard.MEMBERS_MANAGE),
        (web.IDENTITY_PATH, "GET", guard.IDENTITY_READ),
        (web.IDENTITY_PATH + "/bind", "POST", guard.IDENTITY_MANAGE),
        (web.IDENTITY_PATH + "/{binding_id}/disable", "POST", guard.IDENTITY_MANAGE),
    ],
)
def test_each_route_enforces_its_own_permission(
    path: str, method: str, expected: str
) -> None:
    """The exact code, per route.

    Reading members must not require the authority to bind an identity, and —
    the direction that actually matters — binding one must not be reachable
    with only the read permission.
    """
    calls = _dependency_calls(_route(path, method).dependant)
    stamped = {getattr(call, PERMISSION_CODE_ATTR, None) for call in calls}
    assert expected in stamped, f"{method} {path} is not stamped with {expected}"


@pytest.mark.parametrize(
    ("path", "method"),
    [
        (web.MEMBERS_PATH, "POST"),
        (web.MEMBERS_PATH + "/{party_id}/revoke", "POST"),
        (web.IDENTITY_PATH + "/bind", "POST"),
        (web.IDENTITY_PATH + "/{binding_id}/disable", "POST"),
    ],
)
def test_no_mutating_route_is_reachable_with_only_a_read_permission(
    path: str, method: str
) -> None:
    """The sensitivity half of the test above.

    Asserting a mutating route carries SOME stamp would pass if it carried the
    read one. This asserts it carries no read-only stamp at all.
    """
    calls = _dependency_calls(_route(path, method).dependant)
    stamped = {getattr(call, PERMISSION_CODE_ATTR, None) for call in calls}
    assert guard.MEMBERS_READ not in stamped
    assert guard.IDENTITY_READ not in stamped


def test_authentication_still_happens_underneath_every_permission() -> None:
    """The permission guard layers over the cookie guard rather than replacing
    it — which is what keeps the UNAUTHENTICATED answer a redirect."""
    from dotmac_workspace.web_auth import require_workspace_auth

    for path, method in (
        (web.MEMBERS_PATH, "GET"),
        (web.IDENTITY_PATH, "GET"),
        (web.IDENTITY_PATH + "/bind", "POST"),
    ):
        assert require_workspace_auth in _dependency_calls(
            _route(path, method).dependant
        ), f"{method} {path} does not authenticate"


def test_an_authenticated_caller_without_the_permission_gets_403(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """403, never a redirect: the caller is already signed in."""
    from fastapi import HTTPException

    monkeypatch.setattr(kernel_deps, "authorize_party", lambda *a, **k: False)
    request = SimpleNamespace(
        cookies={},
        url=SimpleNamespace(path=web.MEMBERS_PATH),
        state=SimpleNamespace(tenant=SimpleNamespace(id=uuid4())),
    )
    party = SimpleNamespace(id=uuid4(), email="a@b.c")
    with pytest.raises(HTTPException) as raised:
        guard.require_members_manage(request, party, db=object())  # type: ignore[arg-type]
    assert raised.value.status_code == 403


# ── 2. the stranding invariant ──────────────────────────────────────────────


def _member(*, roles: tuple[str, ...], bound: bool, active: bool = True):
    party = SimpleNamespace(
        id=uuid4(), display_name="M", email="m@example.net", is_active=active
    )
    binding = (
        SimpleNamespace(
            id=uuid4(),
            party_id=party.id,
            is_active=True,
            subject="s",
            provider_binding="primary",
            bound_by="op",
            bind_reason="r",
        )
        if bound
        else None
    )
    return service.MemberRow(party=party, role_slugs=roles, binding=binding)


ADMIN = service.ADMIN_ROLE_SLUG


def test_a_member_needs_both_halves_to_count_as_able_to_sign_in() -> None:
    """The property the whole invariant rests on.

    A role without a binding cannot log in; a binding without the role gets a
    403 on every screen. Either alone looks finished on the members table, and
    counting either as sufficient is how a "safe" revocation strands a tenant.
    """
    assert _member(roles=(ADMIN,), bound=True).can_sign_in
    assert not _member(roles=(ADMIN,), bound=False).can_sign_in
    assert not _member(roles=(), bound=True).can_sign_in
    assert not _member(roles=(ADMIN,), bound=True, active=False).can_sign_in


def _service_with(rows: list[service.MemberRow], monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(service, "list_members", lambda db, *, tenant: rows)


def test_stranding_is_judged_after_the_change_not_before(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The member being changed is excluded from the count.

    A check that counted the current state would find one able administrator —
    the one about to lose the role — and cheerfully allow the lockout.
    """
    only = _member(roles=(ADMIN,), bound=True)
    _service_with([only], monkeypatch)
    assert service.would_strand_tenant(
        object(),
        tenant=object(),
        losing_party_id=only.party.id,  # type: ignore[arg-type]
    )


def test_a_second_able_administrator_makes_the_change_safe(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first, second = (
        _member(roles=(ADMIN,), bound=True),
        _member(roles=(ADMIN,), bound=True),
    )
    _service_with([first, second], monkeypatch)
    assert not service.would_strand_tenant(
        object(),
        tenant=object(),
        losing_party_id=first.party.id,  # type: ignore[arg-type]
    )


def test_a_colleague_who_cannot_sign_in_does_not_make_it_safe(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The failure this invariant is really for.

    An unbound admin looks like a second administrator on the members table and
    is not one. If this passed, the refusal would be bypassable by adding a
    member and never binding them — which is the easy thing to do by accident.
    """
    able = _member(roles=(ADMIN,), bound=True)
    unbound = _member(roles=(ADMIN,), bound=False)
    _service_with([able, unbound], monkeypatch)
    assert service.would_strand_tenant(
        object(),
        tenant=object(),
        losing_party_id=able.party.id,  # type: ignore[arg-type]
    )


def test_revoking_the_last_administrators_role_is_refused(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    only = _member(roles=(ADMIN,), bound=True)
    role = SimpleNamespace(id=uuid4(), slug=ADMIN)

    class _Session:
        """Answers the two lookups `revoke_role` makes before it decides."""

        def scalars(self, statement: Any):
            entity = statement.column_descriptions[0]["entity"].__name__
            value = {"Party": only.party, "Role": role}.get(entity)
            return SimpleNamespace(first=lambda: value)

        def delete(self, obj: Any) -> None:  # pragma: no cover - must not run
            raise AssertionError("the grant was deleted despite the refusal")

        def flush(self) -> None:  # pragma: no cover
            raise AssertionError("the revocation was flushed despite the refusal")

    monkeypatch.setattr(service, "would_strand_tenant", lambda *a, **k: True)
    with pytest.raises(ConflictError) as raised:
        service.revoke_role(
            _Session(),  # type: ignore[arg-type]
            tenant=SimpleNamespace(id=uuid4()),  # type: ignore[arg-type]
            party_id=only.party.id,
            role_slug=ADMIN,
        )
    assert "lock everyone out" in str(raised.value)


def test_disabling_the_last_usable_binding_is_refused(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Sharper than the role case since a67: disabling revokes the live session
    too, so the lockout is immediate rather than at token expiry."""
    only = _member(roles=(ADMIN,), bound=True)

    class _Session:
        def scalars(self, statement: Any):
            return SimpleNamespace(first=lambda: only.binding)

    monkeypatch.setattr(service, "would_strand_tenant", lambda *a, **k: True)
    monkeypatch.setattr(
        service,
        "disable_binding",
        lambda *a, **k: pytest.fail("the binding was disabled despite the refusal"),
    )
    with pytest.raises(ConflictError) as raised:
        service.disable_binding_for(
            _Session(),  # type: ignore[arg-type]
            tenant=SimpleNamespace(id=uuid4()),  # type: ignore[arg-type]
            binding_id=only.binding.id,
        )
    assert "sign that member out immediately" in str(raised.value)


def test_an_already_disabled_binding_is_not_blocked_by_the_check(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The refusal must not become a wall around inert rows.

    Disabling something already disabled changes nothing and cannot strand
    anybody; refusing it would make the guard look broken and teach operators to
    route around it.
    """
    row = _member(roles=(ADMIN,), bound=True)
    row.binding.is_active = False
    called: list[UUID] = []

    class _Session:
        def scalars(self, statement: Any):
            return SimpleNamespace(first=lambda: row.binding)

    monkeypatch.setattr(service, "would_strand_tenant", lambda *a, **k: True)
    monkeypatch.setattr(
        service,
        "disable_binding",
        lambda db, *, tenant, binding_id: called.append(binding_id) or row.binding,
    )
    service.disable_binding_for(
        _Session(),  # type: ignore[arg-type]
        tenant=SimpleNamespace(id=uuid4()),  # type: ignore[arg-type]
        binding_id=row.binding.id,
    )
    assert called == [row.binding.id]


# ── 3. the evidence ─────────────────────────────────────────────────────────


def test_bound_by_is_never_read_from_the_request() -> None:
    """The evidence rule, checked syntactically rather than by hope.

    `bound_by` says who decided that this external subject is this person. A
    value the browser supplies is a value the operator can set to somebody
    else's name, which makes the record worthless exactly when an audit needs
    it. So the handler must take it from the authenticated party.
    """
    import ast
    import inspect

    source = inspect.getsource(web.bind)
    tree = ast.parse(inspect.cleandoc(source).replace("async def", "def", 1))

    fields_read = {
        node.args[1].value
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "_field"
        and len(node.args) == 2
        and isinstance(node.args[1], ast.Constant)
    }
    assert "bound_by" not in fields_read, (
        "bind() reads bound_by from the request. It must come from the "
        "authenticated operator."
    )
    assert fields_read == {"email", "subject", "reason"}, (
        f"bind() reads {sorted(fields_read)} from the request; expected exactly "
        "email, subject and reason"
    )

    keywords = {
        kw.arg
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        for kw in node.keywords
    }
    assert "bound_by" in keywords, "bind() never passes bound_by to the service"


def test_the_guard_would_notice_if_bound_by_became_a_form_field() -> None:
    """Sensitivity proof for the check above.

    A guard that only ever runs against correct code proves nothing. This feeds
    it the defect it exists to catch and asserts it fires.
    """
    import ast

    bad = ast.parse(
        "def bind(request, member):\n" "    bound_by = _field(request, 'bound_by')\n"
    )
    fields_read = {
        node.args[1].value
        for node in ast.walk(bad)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "_field"
        and len(node.args) == 2
        and isinstance(node.args[1], ast.Constant)
    }
    assert (
        "bound_by" in fields_read
    ), "the detector cannot see a bound_by read even when one is present"
