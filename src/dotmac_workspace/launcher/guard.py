"""The Workspace's own web-auth guard — its own cookie, its own redirect.

ADR-0021 §1 requires the Workspace to share **no database, session, cookie or
guard** with any application. This module is the "no cookie, no guard" half.

## Why not `dotmac_kernel.web_deps.require_web_auth`

That guard reads a cookie literally named `access_token`, which is also what
every product data plane's portal reads. On separate hosts a browser scopes
those separately, so today they cannot collide — but "cannot collide because of
how we happen to deploy it" is not the invariant ADR-0021 states. A Workspace
and a target application served under one parent domain, with a `Domain=`-scoped
cookie, would share a session name, and the containment invariant would then
depend on a deployment detail rather than on the code.

So the Workspace names its cookie `dmws_session` and carries its own guard.

## Two questions, two seams, two answers

`require_workspace_auth` answers **"who are you?"** and nothing else. It
establishes an authenticated person in this tenant and checks no role and no
permission. Its refusal is a redirect to `/login`, because a visitor with no
session can act on that.

`require_applications_read` answers **"may you?"**, over the top of it. The
decision is the declared permission `workspace.applications.read`, owned by the
launcher's manifest, and it is enforced through `dotmac_kernel.deps
.permission_guard` — the authentication-neutral seam (kernel 0.1.0a62) whose
absence was blocker B1. The kernel never learns this cookie's name; this module
never learns how a permission binds to roles. Both halves stay with their owner.

Its refusal is a **403, never a redirect**, and that asymmetry is the point. By
the time authorization runs, `require_workspace_auth` has already succeeded — the
caller IS signed in. Redirecting them to a login page tells a signed-in user to
sign in, which best case is a confusing bounce and worst case is a loop, because
the login sees a valid session and sends them straight back.

Hand-rolling the role query here would still be the wrong fix, and remains
forbidden (`tests/test_adoption_blockers.py` AST-forbids `PartyRoleGrant`,
`Role`, `select` and `execute` in this file). Duplicating kernel authorization
logic in an assembly is how a plane falls behind a kernel security fix — the
failure ADR-0015 recorded against academy. The seam exists precisely so that
this assembly does not have to.

## What is deliberately NOT re-implemented

Token, session and party validation. That is
`dotmac_kernel.deps.authenticate_request` — the ONE seam both the bearer and
cookie flows go through — and this guard calls it rather than re-deriving it.
Any auth-tightening fix (expiry, tenant-claim checks, revocation) lands there
once and this guard receives it. Re-implementing validation here is how a plane
quietly falls behind a security fix, which is exactly the failure ADR-0015
recorded against a hand-built assembly.
"""

from __future__ import annotations

from dotmac_kernel.deps import authenticate_request, get_db, permission_guard
from dotmac_kernel.models import Party
from dotmac_kernel.permissions import PermissionSpec
from dotmac_kernel.web_deps import WebAuthRedirect
from fastapi import Depends, Request
from sqlalchemy.orm import Session

#: The Workspace's session cookie. Deliberately NOT `access_token` — see the
#: module docstring. A test asserts the two never converge.
SESSION_COOKIE = "dmws_session"

#: Where an unauthenticated visitor is sent.
LOGIN_PATH = "/login"

#: The one authorization decision this wave's surface makes: may this member see
#: this tenant's connected-application portfolio. Named here rather than in
#: `feature.py` so the guard below and the manifest that declares it read the
#: same constant — a code that exists in two string literals is a code that will
#: eventually exist in two spellings.
APPLICATIONS_READ = "workspace.applications.read"


def require_workspace_auth(request: Request, db: Session = Depends(get_db)) -> Party:
    """The authenticated Workspace member, or a redirect to the login page.

    Fails closed on every path: no cookie, an invalid or expired token, a tenant
    mismatch, or a non-person party all produce the same redirect. The guard
    never explains which — an error that distinguishes "no such session" from
    "wrong tenant" tells an unauthenticated caller something about the tenant.
    """
    token = request.cookies.get(SESSION_COOKIE)
    if not token:
        raise WebAuthRedirect(request.url.path, login_path=LOGIN_PATH)

    party = authenticate_request(request, db, token=token)
    if party is None:
        raise WebAuthRedirect(request.url.path, login_path=LOGIN_PATH)
    return party


#: The launcher's permission declaration, referenced by the feature manifest.
#:
#: `default_roles` is the code-declared default binding, not a second authority:
#: it says which role slugs hold the permission out of the box, and a later
#: tenant-configurable grant layers over it exactly as a stored setting layers
#: over a spec default. `("admin",)` is the kernel's own default slug, and the
#: Workspace has no second portal-facing role yet — when it grows one, the
#: change is here, in the declaration, not scattered across route guards.
APPLICATIONS_READ_PERMISSION = PermissionSpec(
    code=APPLICATIONS_READ,
    description=(
        "See this tenant's connected-application portfolio in the Workspace "
        "launcher. Visibility only: a tile is inventory, never an entitlement "
        "to enter the target application (ADR-0021 §3)."
    ),
    default_roles=("admin",),
)

#: The launcher's route guard: authenticate with the Workspace's OWN cookie,
#: then authorize the declared permission through the kernel.
#:
#: `denied` is left at the kernel default — a 403 — deliberately. See the module
#: docstring: an authorization refusal must not redirect to login, because the
#: caller is already signed in. A branded HTML 403 would be an equally valid
#: refusal; a redirect would not be one at all.
#:
#: The returned dependency is STAMPED with the permission code, and `create_app`
#: reads that stamp back off every mounted route and validates it against the
#: catalogue built from the installed manifests. So a typo here, or a manifest
#: that stops declaring the code, stops the boot — it never degrades into a
#: mystery 403 on the first request that reaches the page.
require_applications_read = permission_guard(
    APPLICATIONS_READ,
    authenticated_party=require_workspace_auth,
)


__all__ = [
    "APPLICATIONS_READ",
    "APPLICATIONS_READ_PERMISSION",
    "LOGIN_PATH",
    "SESSION_COOKIE",
    "require_applications_read",
    "require_workspace_auth",
]
