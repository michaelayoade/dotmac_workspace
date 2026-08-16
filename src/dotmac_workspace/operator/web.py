"""The supported operator surface: members, roles and identity bindings.

Before this, every administrative act on a live Workspace needed a shell on the
application host. That is a poor control: it is unaudited by the application, it
requires the broadest possible access to perform the narrowest possible task,
and it made "add a colleague" and "recover from a disaster" the same procedure
with the same blast radius. The CLI stays for the second one — see
`identity/cli.py`, which now says so — and this is the first.

## Why there are no `<form>` elements here

`dotmac_kernel.middleware.csrf` validates the `X-CSRF-Token` HEADER against the
`csrf_token` cookie. A plain `<form method="post">` has no hook for attaching a
custom header, so it would 403 — silently, from the operator's point of view.
Every mutating control is therefore `hx-post` with `hx-include`, and
`tests/test_login_surface.py` fails the build if a rendered page contains a bare
form. The screens here are covered by that test, not merely intended to be.

## Why `bound_by` is never a form field

Binding an external subject to a person is the most consequential act on this
plane, and its evidence is `bound_by` + `reason`. `bound_by` is taken from the
authenticated session — never from the browser — because a field the operator
fills in is a field the operator can fill in with somebody else's name, which
makes the evidence worthless precisely when an audit needs it. `reason` IS free
text, because only a human knows why; it is required and not defaulted.

## Why mutations answer 200 with the screen

htmx does not swap a non-2xx response, so a refusal returned as 409 would leave
the operator looking at an unchanged screen with no explanation — the worst
outcome for a safety refusal whose entire purpose is to be READ. These handlers
therefore render the screen with the refusal stated on it. The domain still
raises `ConflictError`; this adapter is what turns it into something a person
sees.
"""

from __future__ import annotations

import html
import json
from uuid import UUID

from dotmac_kernel.deps import get_db
from dotmac_kernel.models import Party
from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session

from dotmac_workspace.identity.config import provider_or_none
from dotmac_workspace.operator import service
from dotmac_workspace.operator.guard import (
    require_identity_manage,
    require_identity_read,
    require_members_manage,
    require_members_read,
)
from dotmac_workspace.page import render_page
from dotmac_workspace.session_contract import LOGOUT_PATH

router = APIRouter()

MEMBERS_PATH = "/operator/members"
IDENTITY_PATH = "/operator/identity"
SCREEN_ID = "operator-screen"

_E = html.escape

#: The role a revoke button asks to remove, as an `hx-vals` JSON literal.
#: Built once from the same constant the service uses, rather than spelled into
#: the markup — a role slug that exists in two places eventually exists in two
#: spellings, and the failure mode is a button that silently revokes nothing.
_ROLE_VALS = json.dumps({"role_slug": service.ADMIN_ROLE_SLUG}).replace("'", "&#39;")


def _shell(*, title: str, screen: str) -> str:
    """The page around a screen, with the nav and the sign-out control.

    Sign-out is `hx-post`, never a link: a CSRF-exempt safe method that a
    third-party page can trigger by loading an image is a forced logout (F7).
    """
    return render_page(
        title=title,
        body=(
            '<nav class="dmws-nav">'
            '<a href="/applications">Applications</a> '
            f'<a href="{MEMBERS_PATH}">Members</a> '
            f'<a href="{IDENTITY_PATH}">Identity</a>'
            "</nav>"
            f'<div id="{SCREEN_ID}">{screen}</div>'
            f'<button type="button" hx-post="{LOGOUT_PATH}" '
            'hx-swap="none">Sign out</button>'
        ),
    )


def _notice(message: str, *, kind: str = "error") -> str:
    """A refusal or confirmation the operator must actually read."""
    if not message:
        return ""
    return (
        f'<p class="dmws-notice dmws-notice--{_E(kind)}" role="alert">'
        f"{_E(message)}</p>"
    )


def _members_screen(rows: list[service.MemberRow], *, notice: str = "") -> str:
    """The members table plus the add-member control.

    The "can sign in" column is the point of the screen. A member with a role
    and no binding looks finished and cannot log in; showing the two facts
    separately is what stops an operator concluding the system is broken.
    """
    if rows:
        body = "".join(
            "<tr>"
            f"<td>{_E(row.party.display_name)}</td>"
            f"<td>{_E(row.party.email or '')}</td>"
            f"<td>{_E(', '.join(row.role_slugs) or '—')}</td>"
            f"<td>{'yes' if row.can_sign_in else 'no'}</td>"
            "<td>"
            + (
                f'<button type="button" class="dmws-revoke" '
                f'hx-post="{MEMBERS_PATH}/{row.party.id}/revoke" '
                f"hx-vals='{_ROLE_VALS}' "
                f'hx-target="#{SCREEN_ID}" hx-swap="innerHTML">'
                f"Revoke {_E(service.ADMIN_ROLE_SLUG)}</button>"
                if service.ADMIN_ROLE_SLUG in row.role_slugs
                else ""
            )
            + "</td></tr>"
            for row in rows
        )
        table = (
            '<table class="dmws-members"><thead><tr>'
            "<th>Name</th><th>Email</th><th>Roles</th><th>Can sign in</th><th></th>"
            f"</tr></thead><tbody>{body}</tbody></table>"
        )
    else:
        table = "<p>This workspace has no members yet.</p>"

    add = (
        '<section class="dmws-add"><h2>Add a member</h2>'
        '<div id="dmws-add-member">'
        '<input name="email" type="email" placeholder="email" autocomplete="off">'
        '<input name="first_name" placeholder="first name" autocomplete="off">'
        '<input name="last_name" placeholder="last name" autocomplete="off">'
        "</div>"
        f'<button type="button" hx-post="{MEMBERS_PATH}" '
        'hx-include="#dmws-add-member input" '
        f'hx-target="#{SCREEN_ID}" hx-swap="innerHTML">Add member</button>'
        "<p>A new member cannot sign in until an external identity is bound "
        "to them on the Identity screen.</p>"
        "</section>"
    )
    return f"<h1>Members</h1>{notice}{table}{add}"


def _identity_screen(
    rows: list[service.MemberRow], *, notice: str = "", issuer: str = ""
) -> str:
    """Bindings, including disabled ones, with their evidence."""
    # Paired rather than filtered in place: a comprehension over `rows` keeps
    # `binding` optional to a type checker even after the `is not None` test,
    # and the honest fix is to carry the narrowed value rather than to assert.
    bindings = [
        (row.party.display_name, row.binding) for row in rows if row.binding is not None
    ]
    if bindings:
        body = "".join(
            "<tr>"
            f"<td>{_E(name)}</td>"
            f"<td><code>{_E(binding.subject)}</code></td>"
            f"<td>{_E(binding.provider_binding)}</td>"
            f"<td>{'active' if binding.is_active else 'disabled'}</td>"
            f"<td>{_E(binding.bound_by or '')}</td>"
            f"<td>{_E(binding.bind_reason or '')}</td>"
            "<td>"
            + (
                f'<button type="button" class="dmws-disable" '
                f'hx-post="{IDENTITY_PATH}/{binding.id}/disable" '
                f'hx-target="#{SCREEN_ID}" hx-swap="innerHTML">Disable</button>'
                if binding.is_active
                else ""
            )
            + "</td></tr>"
            for name, binding in bindings
        )
        table = (
            '<table class="dmws-bindings"><thead><tr>'
            "<th>Member</th><th>Subject</th><th>Provider</th><th>State</th>"
            "<th>Bound by</th><th>Reason</th><th></th>"
            f"</tr></thead><tbody>{body}</tbody></table>"
        )
    else:
        table = "<p>No external identities are bound in this workspace.</p>"

    bind = (
        '<section class="dmws-bind"><h2>Bind an external identity</h2>'
        f"<p>Issuer: <code>{_E(issuer or 'not configured')}</code></p>"
        '<div id="dmws-bind-identity">'
        '<input name="email" type="email" placeholder="member email" '
        'autocomplete="off">'
        '<input name="subject" placeholder="provider subject" autocomplete="off">'
        '<input name="reason" placeholder="why this subject is this person" '
        'autocomplete="off">'
        "</div>"
        f'<button type="button" hx-post="{IDENTITY_PATH}/bind" '
        'hx-include="#dmws-bind-identity input" '
        f'hx-target="#{SCREEN_ID}" hx-swap="innerHTML">Bind</button>'
        "<p>Disabling a binding signs that member out immediately and revokes "
        "every session it issued.</p>"
        "</section>"
    )
    return f"<h1>Identity</h1>{notice}{table}{bind}"


async def _field(request: Request, name: str) -> str:
    form = await request.form()
    return str(form.get(name, "")).strip()


@router.get(MEMBERS_PATH, response_class=HTMLResponse)
def members(
    request: Request,
    member: Party = Depends(require_members_read),
    db: Session = Depends(get_db),
) -> str:
    """The members screen."""
    rows = service.list_members(db, tenant=request.state.tenant)
    return _shell(title="Members", screen=_members_screen(rows))


@router.post(MEMBERS_PATH, response_class=HTMLResponse)
async def add_member(
    request: Request,
    member: Party = Depends(require_members_manage),
    db: Session = Depends(get_db),
) -> str:
    """Add a member, then re-render the screen."""
    tenant = request.state.tenant
    email = await _field(request, "email")
    first_name = await _field(request, "first_name")
    last_name = await _field(request, "last_name")

    notice = ""
    if not (email and first_name and last_name):
        notice = _notice("Email, first name and last name are all required.")
    else:
        try:
            service.add_member(
                db,
                tenant=tenant,
                email=email,
                first_name=first_name,
                last_name=last_name,
            )
            notice = _notice(
                f"Added {email}. They cannot sign in until an external identity "
                "is bound to them.",
                kind="ok",
            )
        except (service.ConflictError, service.NotFoundError, ValueError) as exc:
            notice = _notice(str(exc))

    rows = service.list_members(db, tenant=tenant)
    return _members_screen(rows, notice=notice)


@router.post(MEMBERS_PATH + "/{party_id}/revoke", response_class=HTMLResponse)
async def revoke(
    party_id: UUID,
    request: Request,
    member: Party = Depends(require_members_manage),
    db: Session = Depends(get_db),
) -> str:
    """Revoke a role, unless doing so would strand the tenant."""
    tenant = request.state.tenant
    role_slug = (await _field(request, "role_slug")) or service.ADMIN_ROLE_SLUG

    try:
        service.revoke_role(db, tenant=tenant, party_id=party_id, role_slug=role_slug)
        notice = _notice(f"Removed {role_slug}.", kind="ok")
    except (service.ConflictError, service.NotFoundError) as exc:
        notice = _notice(str(exc))

    rows = service.list_members(db, tenant=tenant)
    return _members_screen(rows, notice=notice)


@router.get(IDENTITY_PATH, response_class=HTMLResponse)
def identity(
    request: Request,
    member: Party = Depends(require_identity_read),
    db: Session = Depends(get_db),
) -> str:
    """The identity screen."""
    rows = service.list_members(db, tenant=request.state.tenant)
    provider = provider_or_none()
    return _shell(
        title="Identity",
        screen=_identity_screen(rows, issuer=provider.issuer if provider else ""),
    )


@router.post(IDENTITY_PATH + "/bind", response_class=HTMLResponse)
async def bind(
    request: Request,
    member: Party = Depends(require_identity_manage),
    db: Session = Depends(get_db),
) -> str:
    """Bind an external subject to a member.

    `bound_by` comes from `member` — the authenticated operator — and is never
    read from the request. See the module docstring.
    """
    tenant = request.state.tenant
    email = await _field(request, "email")
    subject = await _field(request, "subject")
    reason = await _field(request, "reason")
    provider = provider_or_none()

    notice = ""
    if provider is None:
        notice = _notice(
            "No identity provider is configured, so there is no issuer to bind "
            "against."
        )
    elif not (email and subject and reason):
        notice = _notice(
            "Member email, provider subject and a reason are all required. The "
            "reason is the evidence for this decision and is not optional."
        )
    else:
        try:
            service.bind_member(
                db,
                tenant=tenant,
                email=email,
                subject=subject,
                issuer=provider.issuer,
                provider_binding=provider.provider_binding,
                bound_by=member.email or str(member.id),
                reason=reason,
            )
            notice = _notice(f"Bound {subject} to {email}.", kind="ok")
        except (service.ConflictError, service.NotFoundError, ValueError) as exc:
            notice = _notice(str(exc))

    rows = service.list_members(db, tenant=tenant)
    return _identity_screen(
        rows, notice=notice, issuer=provider.issuer if provider else ""
    )


@router.post(IDENTITY_PATH + "/{binding_id}/disable", response_class=HTMLResponse)
def disable(
    binding_id: UUID,
    request: Request,
    member: Party = Depends(require_identity_manage),
    db: Session = Depends(get_db),
) -> str:
    """Disable a binding, unless doing so would strand the tenant."""
    tenant = request.state.tenant
    try:
        service.disable_binding_for(db, tenant=tenant, binding_id=binding_id)
        notice = _notice(
            "Binding disabled. Every session it issued has been revoked.",
            kind="ok",
        )
    except (service.ConflictError, service.NotFoundError) as exc:
        notice = _notice(str(exc))

    rows = service.list_members(db, tenant=tenant)
    provider = provider_or_none()
    return _identity_screen(
        rows, notice=notice, issuer=provider.issuer if provider else ""
    )


__all__ = ["IDENTITY_PATH", "MEMBERS_PATH", "router"]
