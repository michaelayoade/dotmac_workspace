"""Admission to the Workspace portal — the facet-wide decision, and only that.

Kernel 0.1.0a97 makes a legacy browser facet declare an `admission_permission`,
and refuses the composition without one: the compatibility adapter "never infers
an authorization policy". This module is that policy's declaration.

## What it decides, and what it deliberately does not

`workspace.portal.access` answers ONE question, once per request, before any
screen's own guard runs: **may this member be inside the Workspace portal at
all?** It is not a substitute for the four operator codes or the launcher's, and
it must never become one. Those stay exactly as they are:

    workspace.portal.access      may you be in the portal          (this file)
    workspace.applications.read  may you see the portfolio         (launcher)
    workspace.members.read       may you see members               (operator)
    workspace.members.manage     may you add one / change roles    (operator)
    workspace.identity.read      may you see bindings              (operator)
    workspace.identity.manage    may you decide who gets in        (operator)

The distinction is the same one `operator/guard.py` draws between reading and
managing, one level up. Admission is a coarse boundary — the portal is a
different place from the JSON API and from a target application — while every
consequential act inside it keeps its own, narrower code. Collapsing the six
into this one would hand every admitted member the authority to bind an external
identity, which is the most consequential act on this plane.

## Why `identity` declares it and not `launcher` or `operator`

A permission has exactly one declaring module, and this one is facet-wide: it
gates the launcher's screens and the operator's alike. Of the three manifests
that contribute to the facet, `identity` is the only one that is `core=True` —
the launcher and the operator are both deletable surfaces an API-only
deployment drops, and a facet-wide code whose owner can be dropped would read as
belonging to that owner's screens rather than to the portal.

It is also the honest owner on the substance: `identity` is the front door. It
already owns who may begin a ceremony and who holds a session; admission is the
next question in that same sequence, asked of a member who now has one.

## The routes it does NOT gate

The facet's `entry_routes` bypass admission entirely, and must: `/login`, its
POST, and the callback are reached with no session at all, so requiring a
permission there would demand a session in order to obtain one — a redirect
loop, not a control.

`POST /logout` is in that list for a different and sharper reason. It is not a
pre-auth route; it carries `require_workspace_auth` and always will. But if
facet admission also stood in front of it, a member who holds a session and
NOT `workspace.portal.access` could neither enter nor leave: every screen 403s
and the sign-out control 403s with them. `identity/feature.py` already refuses
to let a permission withhold sign-out — "a permission that could withhold that
would be a way to trap somebody in a session" — and this is the same rule,
enforced at the facet instead of at the route.
"""

from __future__ import annotations

from dotmac_kernel.permissions import PermissionSpec

#: The facet-wide admission code. Named here rather than spelled into
#: `assembly.py` and `feature.py` separately — a code that exists in two string
#: literals is a code that will eventually exist in two spellings, and the
#: failure mode is a boot that stops with `UndeclaredPermissionError`.
PORTAL_ACCESS = "workspace.portal.access"

PORTAL_ACCESS_PERMISSION = PermissionSpec(
    code=PORTAL_ACCESS,
    description=(
        "Be admitted to the Workspace portal. A coarse boundary evaluated once "
        "per request, before any screen's own guard: it says the member belongs "
        "inside this workspace's browser surface, never what they may do there. "
        "Seeing the application portfolio, reading members and deciding who "
        "gets in each keep their own narrower permission."
    ),
    #: `("admin",)` is the kernel's own default slug and the same default the
    #: five existing Workspace permissions carry, so adopting a97 admits exactly
    #: the members who could already reach every screen. Admission that started
    #: stricter than the screens behind it would lock out a live deployment on a
    #: dependency bump; admission that started looser would be a widening nobody
    #: asked for. When this plane grows a second portal-facing role, the change
    #: is here, in the declaration.
    default_roles=("admin",),
)

__all__ = ["PORTAL_ACCESS", "PORTAL_ACCESS_PERMISSION"]
