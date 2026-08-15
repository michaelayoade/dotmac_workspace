"""The app launcher — the Workspace's first and, for this wave, only screen.

## What this page is

A tenant administrator's view of their connected-application portfolio: one
tile per launchable binding, each linking to that application's own admin
surface.

## What this page is NOT

> **Directory visibility is not authorization** (ADR-0021 §3).

A tile means *your tenant has this application and our record of it is
believable*. It does not mean the person looking at the screen may enter. When
they follow the link they arrive at the target application unauthenticated as
far as that application is concerned, and it decides — from its own tables,
with its own session, against its own roles — whether to let them in.

Three things this module therefore never does, each of which would break the
containment invariant from the Workspace side:

1. **It never issues a token for a target application.** The link is a plain
   `href` to `binding.admin_url`. No token is minted, appended, or exchanged.
2. **It never reads or writes a grant.** There is no grant to read: the
   directory holds no authorization column, by construction.
3. **It never filters tiles by what the viewer may do THERE.** Filtering is by
   binding state alone. A member who cannot enter an application still sees the
   tile, and finds out at the target's front door — because the Workspace is
   not entitled to an opinion about another application's authorization, and a
   filter would be exactly that opinion, silently applied.

Point 3 is counter-intuitive and deliberate. Hiding a tile would look like a
courtesy and would in fact be the Workspace pre-empting a decision that belongs
to the target. It would also be wrong the moment the target's roles changed,
because the Workspace's copy of the role catalogue is a cache with a staleness
state — which is precisely why it must not be used to gate anything.

`rel="noopener"` on every tile: the target opens without a handle back to this
window.
"""

from __future__ import annotations

import html

from dotmac_application_directory import launchable_bindings
from dotmac_kernel.deps import get_db
from dotmac_kernel.models import Party
from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session

from dotmac_workspace.launcher.guard import require_applications_read

router = APIRouter()


def _tile(*, name: str, instance: str, url: str, stale: bool) -> str:
    """One application tile.

    Every interpolated value is escaped. `admin_url` in particular is
    application-supplied data that reached us over the network, and it is being
    written into an `href` — the one place on this page where unescaped content
    would be an injection rather than a cosmetic defect.
    """
    warning = (
        '<p class="dmws-tile__stale">Details may be out of date.</p>' if stale else ""
    )
    return (
        '<li class="dmws-tile">'
        f'<h2 class="dmws-tile__name">{html.escape(name)}</h2>'
        f'<p class="dmws-tile__instance">{html.escape(instance)}</p>'
        f"{warning}"
        f'<a class="dmws-tile__link" href="{html.escape(url, quote=True)}" '
        'rel="noopener">Open</a>'
        "</li>"
    )


def _page(body: str) -> str:
    return (
        "<!doctype html>"
        '<html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        "<title>Applications — DotMac Workspace</title></head>"
        f"<body><main><h1>Your applications</h1>{body}</main></body></html>"
    )


@router.get("/applications", response_class=HTMLResponse)
def launcher(
    request: Request,
    member: Party = Depends(require_applications_read),
    db: Session = Depends(get_db),
) -> str:
    """The launcher.

    A thin adapter (ADR-0010): it validates, authorizes the VIEWER against the
    Workspace, and delegates to the directory module's service. It contains no
    query of its own.

    Three outcomes, and the middle one is the one people get wrong:

    - **no session** → 302 to `/login`. `require_workspace_auth` reads the
      Workspace's own `dmws_session` cookie and raises `WebAuthRedirect`.
    - **a session without `workspace.applications.read`** → **403**. Never a
      redirect: the caller is already signed in, so sending them to a login page
      is at best a confusing bounce and at worst a loop against a login that
      finds a valid session and returns them here.
    - **authorized** → the page below renders.

    Note what `member` is used for — establishing that someone may see THIS
    tenant's portfolio — and what it is NOT used for: choosing which tiles to
    show. The permission gates the SCREEN. It says nothing about any target
    application, and no tile is filtered by it. See the module docstring.
    """
    tenant = request.state.tenant
    bindings = launchable_bindings(db, tenant_id=tenant.id)

    if not bindings:
        return _page("<p>No applications are connected to this workspace yet.</p>")

    tiles = "".join(
        _tile(
            name=binding.application_code,
            instance=binding.instance_ref,
            url=binding.admin_url,
            # Surfaced, never acted on: a stale record is a reason to tell the
            # administrator, not a reason to withhold the tile.
            stale=binding.reconciliation_status != "fresh",
        )
        for binding in bindings
    )
    return _page(f'<ul class="dmws-tiles">{tiles}</ul>')


__all__ = ["router"]
