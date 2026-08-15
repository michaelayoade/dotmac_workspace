"""The launcher's authorization decision — "may you?", and nothing else.

## Two questions, two seams, two answers

`dotmac_workspace.web_auth.require_workspace_auth` answers **"who are you?"**.
It reads the Workspace's own `dmws_session` cookie, delegates validation to
`dotmac_kernel.deps.authenticate_request`, and refuses with a redirect to
`/login` — because a visitor with no session can act on that. It lives at the
ASSEMBLY level, not here, because every surface asks it and no feature should
have to import another feature to authenticate. See that module for why the
cookie is not `access_token`, and `dotmac_workspace.session_contract` for where
the name itself lives.

It moved there when the identity feature arrived. What stayed here is what is
the launcher's: the permission it declares, and the guard stamped with it.

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

Hand-rolling the role query would still be the wrong fix, and remains forbidden
in this file AND in `web_auth.py` — `tests/test_adoption_blockers.py` AST-forbids
`PartyRoleGrant`, `Role`, `select`, `execute`, `scalars` and `query` in both.
Duplicating kernel authorization logic in an assembly is how a plane falls
behind a kernel security fix: the failure ADR-0015 recorded against academy. The
seam exists precisely so that this assembly does not have to.
"""

from __future__ import annotations

from dotmac_kernel.deps import permission_guard
from dotmac_kernel.permissions import PermissionSpec

from dotmac_workspace.session_contract import LOGIN_PATH, SESSION_COOKIE
from dotmac_workspace.web_auth import require_workspace_auth

#: The one authorization decision this wave's surface makes: may this member see
#: this tenant's connected-application portfolio. Named here rather than in
#: `feature.py` so the guard below and the manifest that declares it read the
#: same constant — a code that exists in two string literals is a code that will
#: eventually exist in two spellings.
APPLICATIONS_READ = "workspace.applications.read"


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
