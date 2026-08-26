"""The declared browser facet, and the four things about it that are load-bearing.

Kernel 0.1.0a97 turned this assembly's web surface from something the kernel
inferred into something the assembly declares. The kernel validates the SHAPE of
that declaration at boot — an undeclared admission permission, a cookie path
that does not cover the facet, an entry route naming a function that does not
exist, all stop `create_app`. What the kernel cannot check is whether the
declaration says the right thing, and the wrong answers here are all quiet:

* the wrong cookie name authenticates against a cookie nothing sets, so every
  member appears signed out;
* a missing entry route makes `/login` demand a session in order to obtain one;
* an admission permission that replaced the per-route codes would hand every
  admitted member the authority to bind an external identity;
* a URL prefix read as a route prefix would look like it moved every public URL.

Each is asserted below, against the spec the assembly actually builds.
"""

from __future__ import annotations

from dotmac_kernel.web_surfaces import (
    BrowserCredentialTransport,
    BrowserSecurityPlane,
)

from dotmac_workspace.assembly import build_spec
from dotmac_workspace.identity.admission import PORTAL_ACCESS
from dotmac_workspace.identity.feature import feature as identity_feature
from dotmac_workspace.launcher.guard import APPLICATIONS_READ
from dotmac_workspace.operator.guard import (
    IDENTITY_MANAGE,
    IDENTITY_READ,
    MEMBERS_MANAGE,
    MEMBERS_READ,
)
from dotmac_workspace.session_contract import (
    CALLBACK_PATH,
    LOGIN_PATH,
    LOGOUT_PATH,
    SESSION_COOKIE,
)

SPEC = build_spec()
FACETS = {facet.code: facet for facet in SPEC.web_facets}
PROFILES = {profile.code: profile for profile in SPEC.authentication_profiles}
STAFF = FACETS["staff_admin"]
PROFILE = PROFILES[STAFF.authentication_profile]


def test_the_facet_is_spelled_staff_admin() -> None:
    """Not a name this assembly may choose.

    `web_surfaces._legacy_surface` is staff-admin-only by construction — the v1
    compatibility adapter "preserves absolute routers and path navigation for
    one compatibility generation", and only under that code. A facet spelled
    anything else leaves all three `web_routers` manifests without a home and
    the boot stops with `UnknownFacetError`.
    """
    assert set(FACETS) == {"staff_admin"}


# ── the cookie ──────────────────────────────────────────────────────────────


def test_the_facet_authenticates_against_the_workspaces_own_cookie() -> None:
    """`dmws_session`, never `access_token` (ADR-0021 §1, AGENTS.md §2).

    The kernel ships `TENANT_COOKIE_AUTHENTICATION`, whose session policy names
    `access_token` — what every product data plane's portal reads. Binding it
    here would make this plane's containment a deployment coincidence again, and
    it would fail in the least legible way available: the facet would
    authenticate correctly, against a cookie this assembly never sets.
    """
    assert PROFILE.session is not None
    assert PROFILE.session.cookie_name == SESSION_COOKIE == "dmws_session"
    assert PROFILE.session.cookie_name != "access_token"


def test_the_session_policy_describes_the_cookie_that_is_actually_set() -> None:
    """A policy is a description the kernel reasons from, not a second writer.

    `identity.session` sets the cookie `HttpOnly`, `SameSite=Lax`, path `/`, and
    with no `Domain`. A policy claiming anything narrower would be a description
    that had drifted from the `Set-Cookie` header, and the kernel would reason
    about a scope the browser does not enforce.
    """
    assert PROFILE.session is not None
    assert PROFILE.session.cookie_path == "/"
    assert PROFILE.session.http_only is True
    assert PROFILE.session.same_site == "lax"
    assert PROFILE.transport is BrowserCredentialTransport.COOKIE_SESSION


def test_the_facet_enters_the_tenant_plane_and_not_the_platform_one() -> None:
    """A Workspace member is a `Party` in one tenant, under RLS. The platform
    plane belongs to the separate `platform_admin` facet the kernel composes."""
    assert PROFILE.security_plane is BrowserSecurityPlane.TENANT


def test_the_provider_routes_through_the_one_authentication_seam() -> None:
    """Never a second token validation (AGENTS.md §4).

    `require_workspace_auth` calls `dotmac_kernel.deps.authenticate_request`, so
    an auth-tightening fix there — expiry, tenant claims, revocation — reaches
    this facet for free. A provider that validated a token itself would be how
    this plane falls behind a kernel security fix.
    """
    from dotmac_workspace.web_auth import require_workspace_auth

    assert PROFILE.provider is not None
    assert PROFILE.provider.dependency is require_workspace_auth


# ── admission ───────────────────────────────────────────────────────────────


def test_admission_is_declared_by_an_installed_manifest() -> None:
    """`create_app` calls `permission_catalogue.require(...)` on it, so an
    undeclared code stops the boot rather than quietly admitting everybody."""
    assert STAFF.admission_permission == PORTAL_ACCESS
    declared = {spec.code for spec in identity_feature.permissions}
    assert PORTAL_ACCESS in declared


def test_admission_did_not_replace_the_per_route_permissions() -> None:
    """Five narrower codes, still guarding what they guarded.

    Admission is a coarse boundary — the portal is a different place from the
    JSON API. Collapsing the five into it would hand every admitted member
    `workspace.identity.manage`, which decides who gets into this workspace at
    all, and is the single most consequential authority on this plane.
    """
    declared = {
        spec.code
        for module in SPEC.modules
        for spec in getattr(module, "permissions", ())
    }
    for code in (
        APPLICATIONS_READ,
        MEMBERS_READ,
        MEMBERS_MANAGE,
        IDENTITY_READ,
        IDENTITY_MANAGE,
    ):
        assert code in declared, f"{code} lost its declaration"
    assert PORTAL_ACCESS not in {
        APPLICATIONS_READ,
        MEMBERS_READ,
        MEMBERS_MANAGE,
        IDENTITY_READ,
        IDENTITY_MANAGE,
    }


# ── the routes reached before admission ─────────────────────────────────────


def _entry(route_name: str) -> bool:
    return any(reference.route_name == route_name for reference in STAFF.entry_routes)


def test_the_whole_login_ceremony_is_reachable_without_a_session() -> None:
    """Otherwise the facet demands a session in order to obtain one.

    All three legs: the page, the POST that starts the ceremony, and the
    callback the identity provider redirects to. A callback left out of this
    list would refuse every real login at the last step, after the member had
    already authenticated with the provider.
    """
    for route_name in ("login_page", "begin_login", "callback"):
        assert _entry(route_name), (
            f"{route_name} is not an entry route, so reaching it requires the "
            "session it exists to issue"
        )


def test_signing_out_never_requires_the_admission_permission() -> None:
    """A member who holds a session and not `workspace.portal.access` must
    still be able to leave.

    Without this, every screen 403s AND the sign-out control 403s with them:
    the member is trapped in a session, which is the exact outcome
    `identity/feature.py` refuses to let a permission cause. This is not a
    loosening — `POST /logout` keeps `require_workspace_auth`, so it is still
    authenticated; what it escapes is admission.
    """
    assert _entry("logout")


def test_the_named_routes_point_where_this_plane_actually_lives() -> None:
    """`surface.login_path`/`landing_path`/`logout_path` feed the kernel's own
    branded error pages. Unset, they fall back to `/admin` and
    `/admin/logout` — neither of which exists here, so a 403 would offer the
    reader two dead links."""
    assert STAFF.login_route is not None
    assert STAFF.login_route.route_name == "login_page"
    assert STAFF.landing_route is not None
    assert STAFF.landing_route.route_name == "launcher"
    assert STAFF.logout_route is not None
    assert STAFF.logout_route.route_name == "logout"


# ── the prefix, which moves nothing ─────────────────────────────────────────


def test_the_facet_prefix_does_not_claim_this_planes_public_urls() -> None:
    """`url_prefix` is a RESERVATION here, not a description.

    `mount_web_surfaces` includes a legacy surface with `prefix=""`, so this
    value never reaches a URL: `/login`, `/applications` and `/operator/...`
    stay exactly where they are. Asserting that the prefix is NOT a prefix of
    them is what stops somebody "fixing" the apparent inconsistency by moving
    the routes under it.

    It cannot be `/` either, which is what those routes genuinely occupy: the
    kernel refuses two facets whose scopes contain one another, and `/` contains
    the `/platform` facet `create_app` composes whenever
    `platform_surface_enabled` is left at its default.
    """
    assert STAFF.url_prefix != "/"
    for path in (LOGIN_PATH, CALLBACK_PATH, LOGOUT_PATH, "/applications"):
        assert not path.startswith(STAFF.url_prefix), (
            f"{path} sits under the facet prefix {STAFF.url_prefix!r}. The v1 "
            "adapter mounts legacy routers at '' — a prefix that overlapped a "
            "real route would read as though the URL had moved when it had not."
        )


def test_the_ui_contract_is_the_one_the_installed_design_system_publishes() -> None:
    """Selected by the assembly, never discovered by the kernel: `web_surfaces`
    imports no design system and is handed the integer."""
    import dotmac_ui

    assert SPEC.ui_contract_version == dotmac_ui.UI_CONTRACT_VERSION
