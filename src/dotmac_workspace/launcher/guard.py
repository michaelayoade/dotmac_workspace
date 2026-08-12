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

## BLOCKER B1: this guard authenticates, it does not authorize

It establishes that the caller is an authenticated person in this tenant. It
checks **no role and no permission**, so any member of the tenant reaches the
launcher. The intended decision is `workspace.applications.read`, enforced
through a public kernel seam — and no cookie-compatible permission seam exists:
`require_permission` is layered over the BEARER guard, and `require_web_auth`
reads the `access_token` cookie this Workspace must not share while hardcoding
the `"admin"` role.

Hand-rolling the role query here is explicitly the wrong fix: duplicating kernel
authorization logic in an assembly is how a plane falls behind a kernel security
fix. So the gap is recorded as an adoption blocker rather than closed locally —
see `docs/ADOPTION-BLOCKERS.md`, and note that `/applications` must not be
exposed to a real tenant until B1 clears.

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

from dotmac_kernel.deps import authenticate_request, get_db
from dotmac_kernel.models import Party
from dotmac_kernel.web_deps import WebAuthRedirect
from fastapi import Depends, Request
from sqlalchemy.orm import Session

#: The Workspace's session cookie. Deliberately NOT `access_token` — see the
#: module docstring. A test asserts the two never converge.
SESSION_COOKIE = "dmws_session"

#: Where an unauthenticated visitor is sent.
LOGIN_PATH = "/login"


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


__all__ = ["LOGIN_PATH", "SESSION_COOKIE", "require_workspace_auth"]
