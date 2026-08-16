"""What a `dmws_session` is: the Workspace's own session, and only its own.

## One cookie, one session, no sharing (ADR-0021 §1)

The row is a kernel `AuthSession` — the same table `dotmac_kernel.deps
.authenticate_request` validates, which is the point: the Workspace's guard
calls that one seam, so an auth-tightening fix in the kernel (expiry, tenant
claims, revocation) reaches this plane without this plane re-implementing
anything.

The COOKIE is the Workspace's own. `dmws_session`, never `access_token`, and
carrying **no `Domain` attribute** — a host-only cookie. That last detail is
what makes the isolation a property rather than a deployment coincidence: a
`Domain=`-scoped cookie under a shared parent domain would be sent to every
product portal underneath it, and nothing in the code would have changed.

## The window this module closes with `finalize_external_login`

The session is added inside the transaction that still holds the binding's row
lock (`service.complete_login`). That is the only reason a concurrent disable
cannot land between the decision and the session — see the kernel module's
docstring for the interleaving. Nothing here commits; `dotmac_kernel.db` owns
the transaction (hard rule 8), and its commit is what releases the lock and
makes the stamp and the session visible together.

## Session provenance: STAMPED, as of kernel a67

`auth_sessions.external_identity_binding_id` exists in the kernel now, and this
assembly writes it. `issue` REQUIRES `binding_id` — it is not optional and there
is no password path through this module — because contract point 2 says the
value `finalize_external_login` returned is the column's only legitimate source.
A session minted from that call without the stamp is unattributable, and the
kernel cannot enforce that rule since it does not mint sessions.

Waiting for the column was the right call. A Workspace-owned shadow table would
have made this plane a second writer of session revocation, in a different
transaction from the kernel's `disable_external_identity_binding` — precisely
the "two calls a caller can do half of" the contract forbids. The pin moved
instead.

What the stamp buys: disabling a binding now revokes the sessions it produced,
in the kernel, under the same row lock. It is no longer true that a session
outlives the identity it came from.

`binding_id` is ALSO still recorded in the login audit event's details, and that
is not redundant. The column is current state — it says which binding a live
session came from, and disappears with the row. The audit event is history: it
says a session was issued from that binding at a moment in time, and survives
the session being revoked and the row being cleaned up.
"""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID

from dotmac_kernel.models import AuthSession, Party, Tenant
from dotmac_kernel.security import hash_token, issue_access_token
from fastapi import Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from dotmac_workspace.session_contract import (
    CALLBACK_PATH,
    LOGIN_STATE_COOKIE,
    SESSION_COOKIE,
)


def issue(
    db: Session, *, tenant: Tenant, party: Party, binding_id: UUID
) -> tuple[AuthSession, str]:
    """Add a Workspace session for `party`. Returns the row and its token.

    `binding_id` is REQUIRED and has no default. Every session this assembly
    issues comes from a federated login — there is no password path here — so a
    default would exist only to let a caller forget, and the thing they would be
    forgetting is what makes selective revocation possible. It must be the id
    `finalize_external_login` returned, not one the caller had in hand:
    contract point 2, and the difference matters when a subject resolves to a
    different binding than the caller expected.

    Flushes, never commits: the caller's transaction is what makes this and the
    binding stamp visible together, or neither. Only the HASH is stored — the
    token itself exists in the response and in the browser, and nowhere else.

    The row is returned rather than just the token so the caller can record
    WHICH session it issued in the audit trail.
    """
    token, expires_at = issue_access_token(party.id, tenant.id)
    auth_session = AuthSession(
        tenant_id=tenant.id,
        party_id=party.id,
        token_hash=hash_token(token),
        expires_at=expires_at,
        external_identity_binding_id=binding_id,
    )
    db.add(auth_session)
    db.flush()
    return auth_session, token


def revoke(db: Session, *, tenant: Tenant, token: str) -> AuthSession | None:
    """Revoke the session this token names. The row, or `None`.

    Idempotent by construction: it only touches rows that are not already
    revoked, so a double-submitted logout is not an error and a caller need not
    check first. `None` means there was nothing to revoke, which is what an
    expired or already-ended session looks like and is not a failure.
    """
    auth_session = db.scalars(
        select(AuthSession)
        .where(AuthSession.tenant_id == tenant.id)
        .where(AuthSession.token_hash == hash_token(token))
        .where(AuthSession.revoked_at.is_(None))
    ).first()
    if auth_session is None:
        return None
    auth_session.revoked_at = datetime.now(UTC)
    db.flush()
    return auth_session


def attach_cookie(
    response: Response, *, token: str, expires_at: datetime, secure: bool
) -> None:
    """Set `dmws_session` on `response`.

    Every attribute is deliberate:

    * **no `domain`** — host-only, so the cookie cannot reach a product portal
      served under a shared parent domain. This is ADR-0021 §1 expressed as a
      cookie attribute, and it is the one line that must never grow a knob.
    * `httponly` — a session token no script can read.
    * `samesite="lax"` — the member arrives here by a top-level redirect from
      the identity provider and from links; `strict` would make an arrival from
      any external link look signed-out. Nothing that mutates state is a GET
      (logout is a POST under the CSRF header bridge), so `lax` gives away
      nothing.
    * `secure` when the request arrived over TLS, decided by the kernel's
      `is_secure_request` rather than guessed here.
    * `max_age` from the session's own expiry, so the browser forgets the
      cookie when the row stops being valid instead of holding a dead token.
    """
    max_age = max(int((expires_at - datetime.now(UTC)).total_seconds()), 0)
    response.set_cookie(
        key=SESSION_COOKIE,
        value=token,
        max_age=max_age,
        path="/",
        httponly=True,
        samesite="lax",
        secure=secure,
    )


def attach_state_cookie(
    response: Response, *, state: str, expires_at: datetime, secure: bool
) -> None:
    """Set `dmws_login_state` on `response` — the browser half of the state pair.

    This cookie is what makes the callback's `state` parameter mean something.
    Its attributes are chosen for that job and no other:

    * **no `domain`** — host-only, exactly as `attach_cookie` above. A cookie a
      sibling host could set is a cookie an attacker with a foothold on any
      such host could plant, which would hand the attack straight back.
    * `path=CALLBACK_PATH` — the callback is the only route that reads it, so
      it is not sent with any other request. Narrower than the session cookie
      because it can afford to be.
    * `httponly` — nothing in the page has any reason to read it, and a value
      script can read is a value an XSS can exfiltrate and replay.
    * `samesite="lax"` — REQUIRED, not merely acceptable: the callback arrives
      as a top-level cross-site GET redirect from the identity provider, and
      `strict` would withhold the cookie on exactly that navigation, breaking
      every legitimate login. `lax` sends it on top-level GETs and withholds it
      from cross-site subrequests, which is the property this needs.
    * `secure` under TLS, decided by the kernel's `is_secure_request`.
    * `max_age` from the ceremony's own expiry — a state cookie outliving the
      row it names is a value that can only ever produce a refusal.
    """
    max_age = max(int((expires_at - datetime.now(UTC)).total_seconds()), 0)
    response.set_cookie(
        key=LOGIN_STATE_COOKIE,
        value=state,
        max_age=max_age,
        path=CALLBACK_PATH,
        httponly=True,
        samesite="lax",
        secure=secure,
    )


def clear_state_cookie(response: Response, *, secure: bool) -> None:
    """Remove `dmws_login_state`, with the SAME attributes it was set with.

    Cleared on EVERY callback outcome — success, refusal, provider error —
    because a ceremony that has been answered is over either way, and a stale
    state cookie left in the browser is a value that outlives its row.

    Same path/flag rule as `clear_cookie`: a `delete_cookie` whose `path`
    differs leaves the original in place, and here `path` is not `/`.
    """
    response.delete_cookie(
        key=LOGIN_STATE_COOKIE,
        path=CALLBACK_PATH,
        httponly=True,
        samesite="lax",
        secure=secure,
    )


def clear_cookie(response: Response, *, secure: bool) -> None:
    """Remove `dmws_session`, with the SAME attributes it was set with.

    A `delete_cookie` whose path or flags differ from the original leaves the
    original in place — the browser treats them as different cookies — and the
    symptom is a logout that reports success while the session cookie is still
    being sent.
    """
    response.delete_cookie(
        key=SESSION_COOKIE,
        path="/",
        httponly=True,
        samesite="lax",
        secure=secure,
    )


__all__ = [
    "attach_cookie",
    "attach_state_cookie",
    "clear_cookie",
    "clear_state_cookie",
    "issue",
    "revoke",
]
