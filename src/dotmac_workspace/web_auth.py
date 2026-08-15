"""The Workspace's own web-auth guard — its own cookie, its own redirect.

ADR-0021 §1 requires the Workspace to share **no database, session, cookie or
guard** with any application. This module is the "no cookie, no guard" half.

## Why it lives in the assembly rather than in a feature

"Who are you?" is one question for the whole plane. The launcher asks it, the
logout route asks it, and every surface added later will ask it — while the
answer to "may you?" belongs to whichever feature declares the permission being
decided. Splitting them that way is what keeps a feature from importing another
feature to authenticate: they all reach the same assembly-level seam, and no
feature owns the front door.

It moved here from `launcher/guard.py` when the identity feature arrived, for
exactly that reason. The launcher's guard module keeps what is the launcher's:
the permission it declares and the guard stamped with it.

## Why not `dotmac_kernel.web_deps.require_web_auth`

That guard reads a cookie literally named `access_token`, which is also what
every product data plane's portal reads. On separate hosts a browser scopes
those separately, so today they cannot collide — but "cannot collide because of
how we happen to deploy it" is not the invariant ADR-0021 states. A Workspace
and a target application served under one parent domain, with a `Domain=`-scoped
cookie, would share a session name, and the containment invariant would then
depend on a deployment detail rather than on the code.

So the Workspace names its cookie `dmws_session` and carries its own guard.

## What is deliberately NOT re-implemented

Token, session and party validation. That is
`dotmac_kernel.deps.authenticate_request` — the ONE seam both the bearer and
cookie flows go through — and this guard calls it rather than re-deriving it.
Any auth-tightening fix (expiry, tenant-claim checks, revocation) lands there
once and this guard receives it. Re-implementing validation here is how a plane
quietly falls behind a security fix, which is exactly the failure ADR-0015
recorded against a hand-built assembly.

Authorization is likewise not re-implemented: no role query lives here, and
`tests/test_adoption_blockers.py` AST-forbids one in this file and in the
launcher's guard alike.
"""

from __future__ import annotations

from dotmac_kernel.deps import authenticate_request, get_db
from dotmac_kernel.models import Party
from dotmac_kernel.web_deps import WebAuthRedirect
from fastapi import Depends, Request
from sqlalchemy.orm import Session

from dotmac_workspace.session_contract import LOGIN_PATH, SESSION_COOKIE


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


__all__ = ["require_workspace_auth"]
