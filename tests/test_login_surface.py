"""The front door's surface: methods, the cookie, and what never mutates on a GET.

Three properties, and the third is the one that goes wrong quietly.

1. The four routes exist with the methods the flow requires.
2. `dmws_session` is set host-only, `HttpOnly`, `SameSite=Lax`, and cleared
   with the SAME attributes it was set with.
3. Nothing mutates session state on a GET, and no page contains a bare
   `<form method="post">` — which would have no hook for the CSRF header and
   would simply 403.
"""

from __future__ import annotations

import inspect
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from fastapi import Response

from dotmac_workspace.identity import config, session, web
from dotmac_workspace.identity.config import ProviderConfig
from dotmac_workspace.identity.feature import feature
from dotmac_workspace.launcher import web as launcher_web
from dotmac_workspace.session_contract import (
    CALLBACK_PATH,
    LOGIN_PATH,
    LOGIN_STATE_COOKIE,
    LOGOUT_PATH,
    SESSION_COOKIE,
)

CONFIG = ProviderConfig(
    issuer="https://idp.example.net",
    client_id="dotmac-workspace",
    redirect_url="https://ws.example.net/login/callback",
    provider_binding="primary",
    scopes="openid",
    discovery_url="https://idp.example.net/.well-known/openid-configuration",
    http_timeout_seconds=10.0,
    metadata_ttl_seconds=900,
    ceremony_ttl_seconds=600,
    clock_skew_seconds=60,
)


def _rendered_pages() -> dict[str, str]:
    """The actual HTML these routes emit.

    Rendered output, never module source. The guards below look for a bare
    `<form method="post">`, and `identity/web.py`'s docstring explains at
    length why there must not be one — quoting the exact markup it forbids. A
    text scan of the source would flag that explanation, and the cheapest way
    to satisfy such a guard is to delete it. Rendering is the syntax-specific
    check: a docstring is not in the response body.
    """
    config.install(CONFIG)
    try:
        return {
            "login": web.login_page(tenant=object(), next_path="").body.decode(),
            "refusal": web._refusal("no", status_code=403).body.decode(),
            "launcher": launcher_web._page("<p>none</p>"),
        }
    finally:
        config.install(None)


def _methods(path: str) -> set[str]:
    """Every method mounted at `path`, across ALL routes that answer it.

    The union, not the first match: `GET /login` and `POST /login` are two
    separate `APIRoute`s sharing a path, and a helper that returned the first
    one it found would report `{"GET"}` for a surface that also answers POST.
    """
    found = {
        method
        for route in web.router.routes
        if getattr(route, "path", None) == path
        for method in getattr(route, "methods", set())
    }
    if not found:
        raise AssertionError(f"no route mounted at {path}")
    return found


# ── 1. the routes ───────────────────────────────────────────────────────────


def test_the_login_surface_is_mounted_by_the_identity_manifest() -> None:
    """The manifest is how `create_app` learns these routes exist.

    Before this workstream `require_workspace_auth` redirected to a `/login`
    that nothing served — blocker B2, and the reason `/applications` was
    unreachable end to end.
    """
    assert web.router in tuple(feature.web_routers)


def test_starting_a_login_is_a_post_and_rendering_the_page_is_a_get() -> None:
    """A GET that begins an authentication ceremony is login CSRF: a
    third-party page could trigger it with an `<img src=…>` and silently sign a
    victim in as somebody else."""
    assert "GET" in _methods(LOGIN_PATH)
    assert "POST" in _methods(LOGIN_PATH)


def test_logout_is_a_post_and_never_a_get() -> None:
    """A CSRF-exempt safe method a third-party page can trigger by loading an
    image is a forced logout. There is no "logout is special" exemption."""
    methods = _methods(LOGOUT_PATH)
    assert methods == {"POST"}, (
        f"/logout answers {sorted(methods)}. Ending a session is a mutation and "
        "must stay a POST under the CSRF header bridge."
    )


def test_the_callback_is_a_get_because_the_protocol_says_so() -> None:
    """The authorization-code flow ends in a browser redirect, so the method is
    not this assembly's to choose. What protects it is the PAIR: the opaque
    single-use state, which no forged callback can produce, AND the host-only
    cookie holding the same value, which an attacker cannot write onto somebody
    else's browser. The state alone would leave the callback open to login CSRF
    — see `tests/test_login_csrf.py`."""
    assert _methods(CALLBACK_PATH) == {"GET"}


# ── 2. the cookie ───────────────────────────────────────────────────────────


def _set_cookie_header(secure: bool) -> str:
    response = Response()
    session.attach_cookie(
        response,
        token="a.b.c",
        expires_at=datetime.now(UTC) + timedelta(hours=1),
        secure=secure,
    )
    return response.headers["set-cookie"]


def test_the_session_cookie_is_the_workspaces_own() -> None:
    assert SESSION_COOKIE == "dmws_session"
    assert SESSION_COOKIE != "access_token"
    assert SESSION_COOKIE in _set_cookie_header(secure=True)


def test_the_session_cookie_carries_no_domain_attribute() -> None:
    """The one line that must never grow a knob.

    A `Domain=`-scoped cookie under a shared parent domain would be sent to
    every product portal underneath it, and ADR-0021 §1's containment would
    become a deployment coincidence rather than a property of the code.
    """
    header = _set_cookie_header(secure=True).lower()
    assert "domain=" not in header, (
        "the Workspace session cookie declared a Domain. Host-only is what "
        "keeps this plane's session out of every product portal served under "
        "the same parent domain."
    )


def test_the_session_cookie_is_httponly_and_lax() -> None:
    header = _set_cookie_header(secure=True).lower()
    assert "httponly" in header
    assert "samesite=lax" in header
    assert "path=/" in header


def test_secure_tracks_the_request_scheme_rather_than_being_assumed() -> None:
    assert "secure" in _set_cookie_header(secure=True).lower()
    assert "secure" not in _set_cookie_header(secure=False).lower()


def test_clearing_uses_the_same_attributes_as_setting() -> None:
    """A `delete_cookie` whose path or flags differ leaves the original in
    place — the browser treats them as different cookies — and the symptom is a
    logout that reports success while the session keeps being sent."""
    response = Response()
    session.clear_cookie(response, secure=True)
    cleared = response.headers["set-cookie"].lower()
    assert SESSION_COOKIE in cleared
    assert "path=/" in cleared
    assert "httponly" in cleared
    assert "samesite=lax" in cleared
    assert "domain=" not in cleared


# ── 2b. the ceremony cookie ─────────────────────────────────────────────────


def _state_cookie_header(secure: bool) -> str:
    response = Response()
    session.attach_state_cookie(
        response,
        state="a-ceremony-state",
        expires_at=datetime.now(UTC) + timedelta(minutes=10),
        secure=secure,
    )
    return response.headers["set-cookie"]


def test_the_state_cookie_is_host_only_httponly_and_lax() -> None:
    """Each attribute earns its place, and `lax` is REQUIRED rather than merely
    acceptable: the callback arrives as a top-level cross-site GET redirect
    from the identity provider, and `strict` would withhold the cookie on
    exactly that navigation — breaking every legitimate login while appearing
    to be the safer setting."""
    header = _state_cookie_header(secure=True).lower()
    assert LOGIN_STATE_COOKIE in header
    assert "httponly" in header
    assert "samesite=lax" in header
    assert "domain=" not in header, (
        "the ceremony cookie declared a Domain. A cookie a sibling host can "
        "set is a cookie an attacker with a foothold on any such host can "
        "plant — which hands the CSRF attack straight back."
    )


def test_the_state_cookie_is_scoped_to_the_callback_alone() -> None:
    """Only one route reads it, so it is sent to only one route."""
    header = _state_cookie_header(secure=True).lower()
    assert f"path={CALLBACK_PATH}".lower() in header


def test_the_state_cookie_is_secure_under_tls_and_not_otherwise() -> None:
    assert "secure" in _state_cookie_header(secure=True).lower()
    assert "secure" not in _state_cookie_header(secure=False).lower()


def test_clearing_the_state_cookie_uses_the_same_attributes() -> None:
    """`path` here is NOT `/`, so a mismatch is easier to make and has the same
    consequence: the original cookie stays in the browser."""
    response = Response()
    session.clear_state_cookie(response, secure=True)
    cleared = response.headers["set-cookie"].lower()
    assert LOGIN_STATE_COOKIE in cleared
    assert f"path={CALLBACK_PATH}".lower() in cleared
    assert "httponly" in cleared
    assert "samesite=lax" in cleared
    assert "domain=" not in cleared


def test_the_state_cookie_is_not_the_session_cookie() -> None:
    """Two values, two lifetimes, two paths. Reusing one name would make the
    callback's clear-on-completion delete the session it just issued."""
    assert LOGIN_STATE_COOKIE != SESSION_COOKIE


def test_every_callback_outcome_clears_the_state_cookie() -> None:
    """A ceremony that has been answered is over, whichever way it went, and a
    state cookie left behind can only ever produce a later refusal.

    Asserted against the route's SYNTAX rather than by driving four responses:
    every `return` in `callback` must go through the one helper that clears it,
    so a new refusal branch cannot forget.
    """
    import ast
    import inspect

    tree = ast.parse(inspect.getsource(web.callback))
    returns = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Return) and node.value is not None
    ]
    # The helper's own `return response` is one of them.
    wrapped = [
        node
        for node in returns
        if isinstance(node.value, ast.Call)
        and isinstance(node.value.func, ast.Name)
        and node.value.func.id == "_done"
    ]
    assert len(wrapped) == len(returns) - 1, (
        "a `return` in the callback does not pass through `_done`, so that "
        "outcome leaves the ceremony cookie in the browser"
    )
    assert len(wrapped) >= 4, (
        f"only {len(wrapped)} wrapped returns — the callback's refusal branches "
        "have moved and this guard is no longer watching them"
    )


# ── 3. no mutation on a GET, no bare form ───────────────────────────────────


@pytest.mark.parametrize("name", ["login", "refusal", "launcher"])
def test_no_rendered_page_contains_a_bare_method_post_form(name: str) -> None:
    """`static/js/csrf.js` attaches `X-CSRF-Token` to htmx requests. A native
    form submit has no hook for a custom header, so a bare `method="post"` form
    would 403 with `csrf_failed` — every mutating control uses `hx-post`."""
    html = _rendered_pages()[name].lower()
    assert 'method="post"' not in html
    assert "method='post'" not in html
    assert "<form" not in html


def test_the_bare_form_guard_does_not_fire_on_prose_forbidding_one() -> None:
    """`identity/web.py`'s docstring quotes the exact markup it forbids.

    Three guards in this programme have flagged the comment explaining the very
    invariant they enforce. This one reads RENDERED OUTPUT, so the explanation
    is invisible to it — and the explanation must survive.
    """
    source = Path(inspect.getfile(web)).read_text(encoding="utf-8")
    assert 'method="post"' in source, (
        "the module must keep quoting the markup it forbids. If this is what "
        "failed, somebody deleted the explanation — which the rendered-output "
        "check exists to make unnecessary."
    )
    for html in _rendered_pages().values():
        assert 'method="post"' not in html.lower()


@pytest.mark.parametrize("name", ["login", "launcher"])
def test_every_mutating_control_is_an_hx_post(name: str) -> None:
    """The positive half: the controls that exist DO use the bridge.

    Without this, a page that rendered no controls at all would pass the guard
    above for entirely the wrong reason.
    """
    assert "hx-post=" in _rendered_pages()[name]


@pytest.mark.parametrize("name", ["login", "refusal", "launcher"])
def test_every_page_loads_the_csrf_header_bridge(name: str) -> None:
    """The bridge is what makes an `hx-post` succeed. A page that shipped the
    control without the script would render a button that silently 403s."""
    html = _rendered_pages()[name]
    assert "/static/js/htmx.min.js" in html
    assert "/static/js/csrf.js" in html


def test_signing_out_is_reachable_from_the_launcher() -> None:
    """A portal nobody can leave is not a closed loop.

    The launcher never imports the identity feature to do it — it renders a URL
    the identity feature owns, which is the same composition rule the fleet
    uses for cross-feature fragments.
    """
    assert f'hx-post="{LOGOUT_PATH}"' in _rendered_pages()["launcher"]
