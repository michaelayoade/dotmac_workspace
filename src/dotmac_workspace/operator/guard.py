"""The operator surface's authorization decisions.

Four codes, in two pairs, and the split is the whole design:

    workspace.members.read     workspace.members.manage
    workspace.identity.read    workspace.identity.manage

## Why read and manage are separate

Someone answering "why can this person not sign in" needs to SEE members and
bindings. Answering it does not require the authority to create one. Keeping
the pair apart is what makes a future helpdesk role expressible at all; a single
`workspace.members` code would force every such person to hold the power to bind
an external identity, which is the most consequential act on this plane.

## Why members and identity are separate

Granting a role decides what somebody may do once they are in. Binding an
external subject decides WHO GETS IN, on the evidence of somebody's judgement
that this Keycloak subject is that person. The second is the act an attacker
wants and the act an audit asks about. They are not the same authority and are
deliberately not spelled the same way.

## Why the refusal is a 403 and never a redirect

Same asymmetry as the launcher: by the time these run, the caller is already
signed in. Sending a signed-in member to `/login` is at best a confusing bounce
and at worst a loop, because the login finds a valid session and returns them.

Every guard is STAMPED with its code, and `create_app` validates each stamp
against the catalogue built from installed manifests — so a code that is not
declared in `feature.py` stops the boot rather than degrading into a mystery
403 on the first request that reaches the screen.
"""

from __future__ import annotations

from dotmac_kernel.deps import permission_guard
from dotmac_kernel.permissions import PermissionSpec

from dotmac_workspace.web_auth import require_workspace_auth

MEMBERS_READ = "workspace.members.read"
MEMBERS_MANAGE = "workspace.members.manage"
IDENTITY_READ = "workspace.identity.read"
IDENTITY_MANAGE = "workspace.identity.manage"


MEMBERS_READ_PERMISSION = PermissionSpec(
    code=MEMBERS_READ,
    description=(
        "See this workspace's members, the roles they hold, and whether each "
        "can actually sign in. Read-only: it confers no ability to add a "
        "member, change a role, or bind an identity."
    ),
    default_roles=("admin",),
)

MEMBERS_MANAGE_PERMISSION = PermissionSpec(
    code=MEMBERS_MANAGE,
    description=(
        "Add a member to this workspace and change the roles they hold. Does "
        "NOT confer the ability to bind an external identity — deciding who "
        "gets in is workspace.identity.manage."
    ),
    default_roles=("admin",),
)

IDENTITY_READ_PERMISSION = PermissionSpec(
    code=IDENTITY_READ,
    description=(
        "See this workspace's external identity bindings, including disabled "
        "ones, with the evidence recorded for each."
    ),
    default_roles=("admin",),
)

IDENTITY_MANAGE_PERMISSION = PermissionSpec(
    code=IDENTITY_MANAGE,
    description=(
        "Bind an external subject to a member, and disable a binding. The most "
        "consequential authority on this plane: a binding decides who gets in, "
        "and disabling one signs that member out immediately (kernel 0.1.0a67)."
    ),
    default_roles=("admin",),
)

PERMISSIONS = (
    MEMBERS_READ_PERMISSION,
    MEMBERS_MANAGE_PERMISSION,
    IDENTITY_READ_PERMISSION,
    IDENTITY_MANAGE_PERMISSION,
)

require_members_read = permission_guard(
    MEMBERS_READ, authenticated_party=require_workspace_auth
)
require_members_manage = permission_guard(
    MEMBERS_MANAGE, authenticated_party=require_workspace_auth
)
require_identity_read = permission_guard(
    IDENTITY_READ, authenticated_party=require_workspace_auth
)
require_identity_manage = permission_guard(
    IDENTITY_MANAGE, authenticated_party=require_workspace_auth
)


__all__ = [
    "IDENTITY_MANAGE",
    "IDENTITY_MANAGE_PERMISSION",
    "IDENTITY_READ",
    "IDENTITY_READ_PERMISSION",
    "MEMBERS_MANAGE",
    "MEMBERS_MANAGE_PERMISSION",
    "MEMBERS_READ",
    "MEMBERS_READ_PERMISSION",
    "PERMISSIONS",
    "require_identity_manage",
    "require_identity_read",
    "require_members_manage",
    "require_members_read",
]
