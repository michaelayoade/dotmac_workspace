"""The `identity` feature manifest — the Workspace's front door.

`core=True`, unlike the launcher. The launcher is a deletable surface: an
API-only Workspace keeps the directory and drops the tiles. The front door is
not deletable in the same sense — a deployment that mounted the launcher and
dropped this feature would serve a `/applications` that redirects to a `/login`
that does not exist, which is precisely the state blocker B2 described. If a
profile ever genuinely wants no HTML surface at all, `web_enabled=False` is the
switch for that, and it drops both together.

## The two audit actions it declares

`workspace.login.succeeded` and `workspace.logout`. Both are written from
`service.py`, in the same change that declares them — a declared code with no
consumer is dead vocabulary (ADR-0008), and `write_audit_event` rejects a code
no installed manifest declares, so the pair has to exist in both directions.

**What is deliberately NOT declared is a refusal action.** A refused login has
no actor: there is no party, and `dotmac_kernel.audit` offers `system`,
`service`, `api_key` and `user` — none of which is true of "somebody the
provider authenticated who is not bound here". Recording it as `system` would
put a caller's defect in the trail as a real actor, which the kernel explicitly
refuses to default to. Refusals are logged server-side instead, with the
subject an operator needs in order to create the binding that fixes it. When
the kernel's actor vocabulary grows a term for an unauthenticated principal,
this is the declaration that should gain a third code.

## No permission

Nothing here is guarded by one, and that is correct rather than an oversight:
`/login` and its callback must be reachable by someone with no session at all,
and `/logout` is guarded by authentication alone — a member who is signed in
may always sign out, and a permission that could withhold that would be a way
to trap somebody in a session.
"""

from __future__ import annotations

from dotmac_kernel.features import FeatureManifest

from dotmac_workspace.identity.service import LOGIN_SUCCEEDED, LOGOUT
from dotmac_workspace.identity.web import router

feature = FeatureManifest(
    name="identity",
    web_routers=[router],
    audit_actions=(LOGIN_SUCCEEDED, LOGOUT),
    core=True,
    enabled_by_default=True,
)

__all__ = ["feature"]
