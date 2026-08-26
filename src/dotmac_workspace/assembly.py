"""The Tenant Workspace's `ProductAssemblySpec` — what this application IS.

ADR-0021 makes `dotmac_workspace` an independent ADR-0003 assembly: the
customer's plane, sitting between the vendor control plane (which issues what
the tenant commercially owns) and the target applications (which evaluate their
own roles).

## It composes `create_app`, it does not hand-build

ADR-0015's fleet-wide rule, and this is the worst possible application to break
it in: an assembly that builds its own FastAPI app silently declines every
control the kernel performs inside `create_app`, and this one's entire job is a
security boundary. Reading a kernel setting is not adopting the behaviour behind
it — academy proved that with a tenant lockdown that was configured, asserted in
config validation, and never armed.

## What it composes

- `dotmac_application_directory.module` — the domain: the tenant's
  connected-application portfolio, its lifecycle, and its reconciliation state.
- `launcher.feature` — the UI facet. Per ADR-0021 the portal is the assembly's
  facet rather than a domain module, which is why the directory ships no
  routers and this feature exists here.
- `operator.feature` — the administration facet: members, roles and identity
  bindings. Same reasoning as the launcher, and the reason the CLI is now a
  recovery path rather than the only way to administer a running deployment.

## It declares its browser surface, rather than being given one

Kernel 0.1.0a97 turned the interactive web surface from something inferred into
something declared. Before it, three manifests carrying `web_routers` were
mounted behind an authentication policy the kernel picked on their behalf and
silently downgraded; a97 refuses to compose that at all, and this file is where
the answer now lives. One facet (`staff_admin`, the only code the v1
compatibility adapter recognises), one authentication profile naming the
Workspace's OWN `dmws_session` cookie, one facet-wide admission permission, one
shell template, and the entry routes that are reached before any of it applies.

The value of writing it down is that each of those is now checked. A facet whose
admission code no manifest declares stops the boot. A profile whose cookie path
does not cover the facet stops the boot. An entry route naming a function that
does not exist stops the boot. None of that was true when the policy was
inferred.

## What it deliberately does not compose

`dotmac-application-access` and signed grant sets. Deferred by ADR-0021 §5 until
the kernel has a generic signed-document mechanism — the licence envelope
verifier is private and hard-wired to its own schema, so the only three moves
available today (import the private verifier, disguise a grant as a licence,
copy the envelope) are all wrong. Until then this Workspace can show a portfolio
and cannot allocate access, and that gap is honest rather than papered over.
"""

from __future__ import annotations

from pathlib import Path

import dotmac_application_directory
import dotmac_ui
from dotmac_kernel.assembly import ProductAssemblySpec
from dotmac_kernel.web_surfaces import (
    AuthenticationProfileBinding,
    BrowserCapabilityProvision,
    BrowserSecurityPlane,
    BrowserSessionPolicy,
    NavigationRegion,
    TemplateRef,
    WebFacetMount,
    WebRouteRef,
)

from dotmac_workspace.identity.admission import PORTAL_ACCESS
from dotmac_workspace.identity.config import configuration_errors
from dotmac_workspace.identity.feature import feature as identity_feature
from dotmac_workspace.identity.secret_bootstrap import install_workspace_secrets
from dotmac_workspace.launcher.feature import feature as launcher_feature
from dotmac_workspace.operator.feature import feature as operator_feature
from dotmac_workspace.page import SHELL_TEMPLATE
from dotmac_workspace.session_contract import SESSION_COOKIE
from dotmac_workspace.web_auth import WORKSPACE_COOKIE_AUTHENTICATION

ASSEMBLY_NAME = "dotmac_workspace"

#: Where this assembly's own static assets live, resolved from the package
#: rather than the working directory — the app runs from `/app` in a container
#: and from a checkout in development, and a relative path would work in
#: exactly one of them.
_STATIC_DIR = Path(__file__).resolve().parent / "static"

#: The facet shell's directory. Same package-relative resolution as the static
#: dir above, and for the same reason.
_TEMPLATE_DIR = Path(__file__).resolve().parent / "templates"

#: The code the kernel's v1 compatibility adapter recognises. It is not a name
#: this assembly may choose: `_legacy_surface` is staff-admin-only by
#: construction, and a facet spelled anything else leaves every legacy
#: `web_routers` manifest without a home — `UnknownFacetError`, at boot.
_STAFF_FACET = "staff_admin"

#: The authentication profile the facet references. One profile, one cookie.
_WORKSPACE_SESSION_PROFILE = "workspace_member_session"

#: `"legacy"` is the surface code the v1 adapter assigns to every manifest that
#: contributes `web_routers` rather than a typed `web_surfaces` contribution. It
#: is fixed by the kernel, not chosen here, and every `WebRouteRef` below spells
#: it — a route reference is (module, surface, route name), and all three halves
#: have to match what `WebSurfaceRegistry` actually registered.
_LEGACY = "legacy"


def build_spec() -> ProductAssemblySpec:
    """Compose the Workspace assembly.

    `identity` is listed FIRST because it is the front door: a deployment that
    somehow mounted the launcher without it would serve an `/applications` that
    redirects to a `/login` that does not exist — which is exactly the state
    blocker B2 described, and the state this workstream closed.

    ## The two startup seams, and why the OIDC secret uses them

    `startup_checks` runs first and follows the kernel's environment policy: a
    warning in development, a fatal error in production. `configuration_errors`
    is therefore how a production Workspace whose members could not log in
    fails to start, rather than starting and looking healthy.

    `startup_hooks` then runs `install_workspace_secrets`, which reads the
    provider configuration and installs the `SecretSource` holding the OIDC
    client secret. Once, inside the lifespan, before a single request is
    served. ADR-0009: a secret is HELD, never dereferenced on a request path,
    so a secret store that becomes unreachable an hour after boot cannot touch
    the login path — and a store that is merely SLOW cannot put its latency on
    every callback.

    Both are kernel seams rather than module-level side effects. Reading a
    secret at import time would run it during `alembic`, during a CLI
    invocation and during collection of every test, none of which needs it.
    """
    return ProductAssemblySpec(
        name=ASSEMBLY_NAME,
        modules=(
            identity_feature,
            launcher_feature,
            operator_feature,
            dotmac_application_directory.module,
        ),
        web_enabled=True,
        # The design system's compiled assets, layered into the existing
        # `/static` mount. The kernel never imports `dotmac_ui` — the assembly
        # fills this slot, which is what keeps the dependency direction one-way.
        packaged_static_dirs=(dotmac_ui.static_dir(),),
        # This assembly's own `.dmws-*` rules, written entirely against
        # `var(--dmui-*)` tokens. Separate from the package's assets because the
        # design system ships tokens and declared components; the markup that
        # consumes them is the product's.
        assembly_static_dir=_STATIC_DIR,
        # The facet's shell lives here. This slot was empty until a97, because
        # the assembly genuinely rendered no Jinja; a declared facet must name a
        # real template and `create_app` resolves it at boot, so the directory
        # has to be composed for the boot to survive.
        assembly_template_dir=_TEMPLATE_DIR,
        # The sibling `stylesheets` slot stays deliberately UNSET, as it was
        # before a97. It feeds a kernel-rendered Jinja global, and every page
        # this assembly serves is composed by `page.render_page`, which emits
        # its own `<link>`s from `page.stylesheets()` — the one place that names
        # the cascade. The shell template reads a caller-supplied `stylesheets`
        # and only falls back to `surface.stylesheets`, so leaving this empty
        # changes nothing about what a member sees.
        #
        # Setting it WOULD also style the kernel's branded error pages, which
        # render this cascade and are currently unstyled. That is a real repair
        # and a real behaviour change, and it is unrelated to adopting a97 — so
        # it belongs in its own change with its own acceptance, not smuggled in
        # on a dependency bump.
        # ── The interactive browser surface (kernel 0.1.0a97) ────────────────
        #
        # One audience, so one facet. Everything this assembly serves in a
        # browser — the launcher, the operator screens and the front door — is
        # for a signed-in member of THIS workspace.
        ui_contract_version=dotmac_ui.UI_CONTRACT_VERSION,
        web_facets=(
            WebFacetMount(
                code=_STAFF_FACET,
                # `/workspace`, and the choice needs stating because the obvious
                # answer is `/` and `/` is refused.
                #
                # This facet's routes are ABSOLUTE — `/login`, `/applications`,
                # `/operator/...` — and they stay absolute: `mount_web_surfaces`
                # includes a LEGACY surface with `prefix=""`, ignoring this
                # value entirely, and `_validate_surfaces` checks a legacy
                # route's own `route.path` rather than a joined one. So no
                # public URL moves whatever is written here, which the route
                # table before and after this change confirms.
                #
                # What the value DOES do is claim a URL scope, and the kernel
                # refuses two facets whose scopes contain one another. `/` would
                # contain `/platform` — the control-plane facet `create_app`
                # composes for every HTML assembly with
                # `platform_surface_enabled` left at its default — and the boot
                # would stop with `DuplicateFacetError`. Turning the platform
                # surface off to win the argument would delete eleven live
                # routes on a dependency bump, which is not this change's to do.
                #
                # So `/workspace` is a RESERVATION, not a description: nothing
                # is served there today, and it is the prefix a contract-v2
                # surface would mount under when this plane migrates off the v1
                # adapter. `SurfaceContext.url_prefix` carries it and nothing in
                # this assembly reads that field.
                url_prefix="/workspace",
                # Jinja template declaration, not subprocess shell execution.
                shell=TemplateRef(SHELL_TEMPLATE),  # nosec B604
                authentication_profile=_WORKSPACE_SESSION_PROFILE,
                # Facet-wide admission, declared by `identity` — see
                # `identity/admission.py` for why it is that manifest's and why
                # it does not replace the five per-route codes, which all stay.
                admission_permission=PORTAL_ACCESS,
                # The region the launcher's and operator's `NavItem`s land in.
                # The v1 adapter puts every legacy nav entry in the facet's
                # first declared region.
                navigation_regions=(NavigationRegion("primary"),),
                # Routes reached with no session, plus one that must not need
                # admission. Without these the facet would demand a session in
                # order to obtain one, and `/login` would redirect to itself.
                #
                # `logout` is here for the OTHER reason, and it is not a
                # loosening: the route keeps `require_workspace_auth`, so it is
                # still authenticated. What it escapes is the admission
                # permission — because a member holding a session and not
                # holding `workspace.portal.access` would otherwise be unable to
                # enter OR leave, which is precisely the "trapped in a session"
                # failure `identity/feature.py` refuses to allow a permission to
                # cause.
                entry_routes=(
                    WebRouteRef("identity", _LEGACY, "login_page"),
                    WebRouteRef("identity", _LEGACY, "begin_login"),
                    WebRouteRef("identity", _LEGACY, "callback"),
                    WebRouteRef("identity", _LEGACY, "logout"),
                ),
                # The three named routes the kernel's own templates fall back on
                # — `surface.login_path`, `surface.landing_path`,
                # `surface.logout_path`. Not decoration: with them unset, every
                # branded kernel error page offers the reader a link to `/admin`
                # and a sign-out button posting to `/admin/logout`, neither of
                # which exists in this plane.
                login_route=WebRouteRef("identity", _LEGACY, "login_page"),
                landing_route=WebRouteRef("launcher", _LEGACY, "launcher"),
                logout_route=WebRouteRef("identity", _LEGACY, "logout"),
            ),
        ),
        authentication_profiles=(
            AuthenticationProfileBinding(
                code=_WORKSPACE_SESSION_PROFILE,
                # NOT `web_deps.TENANT_COOKIE_AUTHENTICATION`, which reads
                # `access_token`. See `web_auth.WorkspaceCookieAuthentication`.
                provider=WORKSPACE_COOKIE_AUTHENTICATION,
                # The one string ADR-0021 §1's containment rests on, read from
                # `session_contract` rather than spelled again here. `cookie_path`
                # is `/` because that is what `identity.session` actually sets —
                # a policy that described a narrower scope than the Set-Cookie
                # header would be a description, not a control.
                session=BrowserSessionPolicy(
                    cookie_name=SESSION_COOKIE, cookie_path="/"
                ),
                # TENANT, not PLATFORM: a Workspace member is a `Party` in one
                # tenant, and the plane the facet enters is the tenant-scoped,
                # RLS-governed one. The platform plane belongs to the separate
                # `platform_admin` facet the kernel composes.
                security_plane=BrowserSecurityPlane.TENANT,
            ),
        ),
        # htmx, declared as a PROVISION: this assembly ships
        # `/static/js/htmx.min.js` on every page and is the party answerable for
        # its browser-security consequences (it has none — no worker, no blob,
        # no frame, so no CSP relaxation is requested).
        #
        # No surface REQUIRES it yet, and cannot: the v1 compatibility adapter
        # synthesises a contribution with no `browser_capabilities` at all, so
        # `browser_security_requirements` is empty today and this provision is
        # not yet load-bearing. It is declared rather than deferred because the
        # requirement side is what a contract-v2 surface adds, and a surface
        # that required a capability the assembly did not provide would fail to
        # compose — the provision is the half that has to exist first.
        browser_capabilities=(BrowserCapabilityProvision("htmx", 2),),
        startup_checks=(configuration_errors,),
        startup_hooks=(install_workspace_secrets,),
    )


__all__ = ["ASSEMBLY_NAME", "build_spec"]
