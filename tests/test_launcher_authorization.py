"""The launcher authorizes, and it refuses in the right shape.

B1 was "there is no cookie-compatible permission seam in the kernel". Kernel
0.1.0a62 added one (`dotmac_kernel.deps.permission_guard`), so the launcher now
declares `workspace.applications.read` and enforces it. These tests pin the
three outcomes and, more importantly, the SHAPE of the middle one.

    no session                  ->  302 to /login
    session, no permission      ->  403          <- never a redirect
    session, with permission    ->  the page

The middle case is the one that goes wrong quietly. A portal that redirects on
an authorization failure tells a signed-in user to sign in: best case a
confusing bounce, worst case a loop, because the login sees a valid session and
sends them straight back. "Who are you?" redirects; "may you?" refuses. The two
answers must not converge.

No database: `authorize_party` is the kernel's one permission decision and is
substituted here, because what is under test is which answer this assembly turns
a `False` into — not the kernel's role arithmetic, which the kernel tests.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any
from uuid import uuid4

import pytest
from dotmac_kernel import deps as kernel_deps
from dotmac_kernel.permissions import PERMISSION_CODE_ATTR
from dotmac_kernel.web_deps import WebAuthRedirect
from fastapi import HTTPException

from dotmac_workspace.launcher import guard, web
from dotmac_workspace.launcher.feature import feature


def _request(*, cookies: dict[str, str] | None = None, path: str = "/applications"):
    """The smallest thing the guards actually read off a request."""
    return SimpleNamespace(
        cookies=cookies or {},
        url=SimpleNamespace(path=path),
        state=SimpleNamespace(tenant=SimpleNamespace(id=uuid4())),
    )


# ── The declaration ─────────────────────────────────────────────────────────


def test_the_launcher_declares_the_permission_it_enforces() -> None:
    """One module owns the code, and it is the module whose route references it.

    `create_app` validates every route's stamped code against the catalogue
    built from installed manifests, so a reference without a declaration stops
    the boot. This asserts the pair exists in the first place.
    """
    declared = {spec.code for spec in feature.permissions}
    assert "workspace.applications.read" in declared
    assert guard.APPLICATIONS_READ_PERMISSION in tuple(feature.permissions)


def test_the_declared_permission_is_reachable() -> None:
    """A permission no role can hold is an unreachable route, not a lockdown."""
    assert tuple(guard.APPLICATIONS_READ_PERMISSION.default_roles)


def test_the_guard_is_stamped_with_the_declared_code() -> None:
    """The stamp IS the boot-time check. An unstamped guard is a route the
    factory cannot validate — it would enforce something nothing declares."""
    assert (
        getattr(guard.require_applications_read, PERMISSION_CODE_ATTR)
        == guard.APPLICATIONS_READ
    )


# ── The wiring ──────────────────────────────────────────────────────────────


def _route(path: str):
    for route in web.router.routes:
        if getattr(route, "path", None) == path:
            return route
    raise AssertionError(f"no route mounted at {path}")


def _dependency_calls(dependant: Any) -> set[Any]:
    """Every callable in a route's dependency tree, at any depth."""
    found: set[Any] = set()
    pending = list(dependant.dependencies)
    while pending:
        sub = pending.pop()
        if sub.call is not None:
            found.add(sub.call)
        pending.extend(sub.dependencies)
    return found


def test_the_applications_route_is_guarded_by_the_permission() -> None:
    calls = _dependency_calls(_route("/applications").dependant)
    stamped = {getattr(call, PERMISSION_CODE_ATTR, None) for call in calls}
    assert guard.APPLICATIONS_READ in stamped, (
        "GET /applications must depend on the permission guard — an "
        "authenticate-only dependency here is exactly the B1 gap reopening"
    )


def test_authentication_still_happens_underneath_the_permission() -> None:
    """The permission guard does not replace the cookie guard, it layers over
    it — which is what keeps the unauthenticated answer a redirect."""
    calls = _dependency_calls(_route("/applications").dependant)
    assert guard.require_workspace_auth in calls


# ── The three outcomes ──────────────────────────────────────────────────────


def test_no_session_is_a_redirect_to_the_workspace_login() -> None:
    with pytest.raises(WebAuthRedirect) as raised:
        guard.require_workspace_auth(_request(), db=object())  # type: ignore[arg-type]
    assert raised.value.status_code == 302
    assert raised.value.login_path == guard.LOGIN_PATH


def test_an_authenticated_caller_without_the_permission_gets_403(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The load-bearing one.

    A redirect here would send a signed-in user to a login page that finds a
    valid session — a loop, and a security control that looks armed while
    telling the user nothing true.
    """
    monkeypatch.setattr(
        kernel_deps, "authorize_party", lambda db, *, tenant, party, code: False
    )
    member = object()
    with pytest.raises(HTTPException) as raised:
        guard.require_applications_read(_request(), member, object())

    assert raised.value.status_code == 403
    assert not isinstance(raised.value, WebAuthRedirect)


def test_an_authorized_caller_is_returned_unchanged(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        kernel_deps, "authorize_party", lambda db, *, tenant, party, code: True
    )
    member = object()
    assert guard.require_applications_read(_request(), member, object()) is member


def test_the_decision_asked_for_is_the_declared_code(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Not a role slug, not `"admin"`, not a hardcoded string — the code the
    manifest declares. The launcher names the DECISION; the declaration decides
    which roles satisfy it."""
    seen: list[str] = []

    def _record(db: object, *, tenant: object, party: object, code: str) -> bool:
        seen.append(code)
        return True

    monkeypatch.setattr(kernel_deps, "authorize_party", _record)
    guard.require_applications_read(_request(), object(), object())
    assert seen == ["workspace.applications.read"]
