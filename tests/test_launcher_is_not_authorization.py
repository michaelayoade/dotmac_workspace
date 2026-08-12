"""The launcher shows applications. It must never grant access to one.

ADR-0021 §3 makes directory visibility distinct from authorization. The starter
repository enforces the DATA half of that rule — the directory has no
authorization column. This file enforces the SURFACE half, which is the one that
would break here: a launcher that appended a token to a tile, or that hid tiles
the viewer "cannot use", would have made the Workspace an identity provider for
its siblings.

Mostly AST-based, deliberately. The property is "this code never does X", and a
behavioural test can only show that it did not do X for the inputs tried.
"""

from __future__ import annotations

import ast
import inspect
from pathlib import Path

from dotmac_workspace.launcher import guard, web

WEB_SOURCE = Path(inspect.getfile(web)).read_text(encoding="utf-8")
GUARD_SOURCE = Path(inspect.getfile(guard)).read_text(encoding="utf-8")


def _called_names(source: str) -> set[str]:
    """Every function/attribute name called anywhere in `source`."""
    names: set[str] = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Name):
                names.add(func.id)
            elif isinstance(func, ast.Attribute):
                names.add(func.attr)
    return names


def test_the_launcher_never_mints_a_token() -> None:
    """A tile is a plain link. No token is created, signed or exchanged.

    If the Workspace ever handed a visitor something the target application
    would accept, the target would no longer be deciding its own access — which
    is the containment invariant, broken from the Workspace side.
    """
    minting = {
        "create_access_token",
        "issue_token",
        "encode",
        "sign",
        "seal",
        "seal_applied_state",
        "create_session",
        "mint",
    }
    assert not (minting & _called_names(WEB_SOURCE)), (
        "the launcher calls a token-minting function; a tile must be a plain "
        "link and nothing more (ADR-0021 §3)"
    )


def test_the_launcher_imports_nothing_that_could_authorize_elsewhere() -> None:
    """No security, licensing or signing import reaches this surface."""
    forbidden = {
        "dotmac_kernel.security",
        "dotmac_kernel.licensing",
        "dotmac_kernel.platform_auth",
        "jwt",
        "jose",
    }
    imported: set[str] = set()
    for node in ast.walk(ast.parse(WEB_SOURCE)):
        if isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module)
        elif isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
    assert not (forbidden & imported), f"launcher imports {forbidden & imported}"


def test_the_tile_link_is_the_admin_url_and_nothing_appended() -> None:
    """No query string, no fragment, no credential smuggled onto the href."""
    rendered = web._tile(
        name="sub",
        instance="sub-lagos-1",
        url="https://sub.example.net/admin",
        stale=False,
    )
    assert 'href="https://sub.example.net/admin"' in rendered
    assert "token" not in rendered.lower()
    assert "?" not in rendered.split('href="')[1].split('"')[0]


def test_the_tile_escapes_application_supplied_content() -> None:
    """`admin_url` and the codes reached us over the network from another
    application, and are being written into an `href` and into markup. This is
    the one place on the page where unescaped content is an injection rather
    than a cosmetic defect."""
    rendered = web._tile(
        name='sub"><script>alert(1)</script>',
        instance="i",
        url='https://x/"><script>alert(2)</script>',
        stale=False,
    )
    assert "<script>" not in rendered
    assert "&lt;script&gt;" in rendered


def test_the_tile_opens_without_a_handle_back_to_this_window() -> None:
    rendered = web._tile(name="s", instance="i", url="https://x/a", stale=False)
    assert 'rel="noopener"' in rendered


def test_the_launcher_filters_by_binding_state_only() -> None:
    """It calls `launchable_bindings`, whose filter is derived from
    `is_launchable` — binding state, never the viewer.

    Filtering by what the viewer may do in the TARGET would be the Workspace
    forming an opinion about another application's authorization, from a cached
    role catalogue that carries a staleness state precisely because it must not
    be used to gate anything.
    """
    called = _called_names(WEB_SOURCE)
    assert "launchable_bindings" in called
    for viewer_filter in ("delegable_role_codes", "has_role", "can_access"):
        assert viewer_filter not in called, (
            f"the launcher filters tiles with {viewer_filter!r} — tile "
            "visibility must depend on binding state alone (ADR-0021 §3)"
        )


def test_a_stale_binding_is_surfaced_not_withheld() -> None:
    """Staleness is told to the administrator, never acted on."""
    stale = web._tile(name="s", instance="i", url="https://x/a", stale=True)
    fresh = web._tile(name="s", instance="i", url="https://x/a", stale=False)
    assert "out of date" in stale
    assert "out of date" not in fresh
    # Both still render a link: a stale record is a caveat, not a block.
    assert 'href="https://x/a"' in stale


# ── The separate-plane half of ADR-0021 §1 ───────────────────────────────────


def test_the_workspace_session_cookie_is_not_the_portal_cookie() -> None:
    """`access_token` is what every product data plane's portal reads.

    On separate hosts a browser scopes those separately, so today they cannot
    collide — but the ADR states an invariant, not a deployment coincidence. A
    Workspace and a target application served under one parent domain with a
    `Domain=`-scoped cookie would share a session name.
    """
    assert guard.SESSION_COOKIE == "dmws_session"
    assert guard.SESSION_COOKIE != "access_token"


def test_the_guard_does_not_reimplement_token_validation() -> None:
    """It delegates to `authenticate_request` — the ONE seam both the bearer and
    cookie flows go through — so an auth-tightening fix lands once and reaches
    here. Re-deriving validation is how a plane falls behind a security fix."""
    assert "authenticate_request" in _called_names(GUARD_SOURCE)
    for reimplementation in ("decode", "verify_signature", "parse_token"):
        assert reimplementation not in _called_names(GUARD_SOURCE)


def test_the_guard_fails_closed_to_a_redirect_on_every_path() -> None:
    """No cookie and an invalid token produce the SAME outcome. A guard that
    distinguished them would tell an unauthenticated caller something."""
    raised = [
        node
        for node in ast.walk(ast.parse(GUARD_SOURCE))
        if isinstance(node, ast.Raise)
    ]
    assert len(raised) == 2, "expected exactly the no-cookie and no-party paths"
    for node in raised:
        assert isinstance(node.exc, ast.Call)
        assert isinstance(node.exc.func, ast.Name)
        assert node.exc.func.id == "WebAuthRedirect"
