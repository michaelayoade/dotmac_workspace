"""The login flow — the Workspace's own, start to finish.

`web.py` validates and delegates; the decisions are here (AGENTS.md §5).

## The whole flow, and where each guarantee comes from

    POST /login          begin_login   -> opaque state stored, browser sent away
    GET  /login/callback complete_login-> state consumed once, code redeemed,
                                          ID token verified, binding finalized,
                                          session minted in the SAME transaction
    POST /logout         end_session   -> session revoked, cookie cleared

| guarantee | who provides it |
|---|---|
| the callback belongs to the browser that started | PKCE S256, `oidc` |
| the ID token belongs to THIS ceremony | `nonce`, `oidc` |
| a ceremony is used at most once, on any worker | `DELETE … RETURNING`, `state_store` |
| an unbound subject cannot log in | `finalize_external_login` returning `None` |
| a disable cannot race a login | `finalize_external_login`'s row lock |
| the session cannot outrun the decision | one transaction, one commit |

## `finalize_external_login`, never `resolve_external_identity`

This is the load-bearing line of the whole workstream, so it is worth being
blunt about what the alternative does.

    resolved = resolve_external_identity(...)  # binding active, party a person
    ── an administrator disables the binding, and commits ──
    db.add(AuthSession(...))                   # a live session, revoked identity

Both halves look successful. The disable really did deactivate the row and
every later resolution really does refuse; the login really did authenticate
somebody the binding named. Nothing in either audit trail contradicts the
other, because what makes them incompatible is an ORDERING that neither one
records. Carrying `binding_id` across the gap does not help — the window is
between a read and the write that depends on it, and a value read before the
window is still a value read before the window.

`finalize_external_login` makes the read a `SELECT … FOR UPDATE`. The disable
path's `UPDATE` needs the same row lock, so the two serialize:

* the login takes the lock first — the session is issued, and the disable
  commits behind it against a binding that has already authenticated; or
* the disable takes the lock first — the login blocks, re-reads `is_active =
  False` UNDER the lock, and refuses.

There is no interleaving that mints a session from a binding that was already
inactive when the login took the lock. `tests/test_login_flow.py
::test_the_callback_uses_the_locking_finalizer` pins the call, and
`tests/test_no_resolve_then_issue.py` proves by AST that the racy pair does not
appear anywhere in this repository.

What the lock does NOT close is named rather than implied: a session issued a
minute earlier is untouched, because retracting it needs session provenance and
that column lives on a kernel table (see `session.py` and
`docs/ADOPTION-BLOCKERS.md`).

## No JIT provisioning, no email linking

An unbound subject is refused. Nothing here creates a party, and nothing
matches on email — the kernel refuses to, and this module never asks. Binding
is a separate, evidenced, administrative act (`cli.py`). The cost is that a new
member cannot log in until an operator binds them; the alternative is that
anyone the provider will authenticate becomes a member, which is not a login
path but a registration one wearing a convenience argument.

## Every refusal is the same refusal

`LoginRefused` carries no reason a caller can branch on. Distinguishing "no
such subject" from "disabled binding" from "bad nonce" hands whoever can drive
a login an oracle for which subjects exist. The reasons are logged
server-side — including the subject, which an operator needs in order to create
the binding that fixes it — and never rendered.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from uuid import UUID

from dotmac_kernel.audit import write_audit_event
from dotmac_kernel.external_identity import finalize_external_login
from dotmac_kernel.models import Party, Tenant
from sqlalchemy.orm import Session

from dotmac_workspace.identity import oidc, session
from dotmac_workspace.identity.config import ProviderConfig, provider
from dotmac_workspace.identity.state_store import (
    LoginCeremony,
    PostgresStateStore,
    StateStore,
)

logger = logging.getLogger(__name__)

#: Declared by this feature's manifest, and written from here. Both have a real
#: consumer in the same change that declares them (ADR-0008).
LOGIN_SUCCEEDED = "workspace.login.succeeded"
LOGOUT = "workspace.logout"

#: The shared, atomic store. A module-level singleton because it holds no
#: state — every method takes the caller's session — and because the ONE thing
#: that must never be configurable is which store a production process uses.
_STORE: StateStore = PostgresStateStore()


class LoginRefused(Exception):
    """The ceremony did not produce a session. One type, no reason field."""


@dataclass(frozen=True, slots=True)
class CompletedLogin:
    """A finished login: who, which session, and where they were going."""

    party: Party
    token: str
    expires_at: datetime
    return_path: str
    binding_id: UUID


def begin_login(
    db: Session,
    *,
    tenant: Tenant,
    return_path: str,
    store: StateStore = _STORE,
    config: ProviderConfig | None = None,
) -> str:
    """Start a ceremony and return where to send the browser.

    `return_path` has already been reduced to a same-origin absolute path by
    the adapter (`dotmac_kernel.web_deps.safe_next_url`). It is stored HERE
    rather than carried through the provider, so nothing the provider echoes
    back can turn the landing into an open redirect.

    Raises `LoginRefused` when the provider cannot be reached — a discovery
    document that will not load is an unreachable identity provider, not a
    defect in this process, and it must surface as a refusal rather than as a
    500 whose traceback names an HTTP client.
    """
    resolved = config or provider()
    state = oidc.new_state()
    ceremony = LoginCeremony(
        code_verifier=oidc.new_code_verifier(),
        nonce=oidc.new_nonce(),
        return_path=return_path,
        provider_binding=resolved.provider_binding,
    )
    try:
        # Discovery BEFORE the row: a ceremony written for a login that could
        # never start is a row nobody will consume, kept alive until it
        # expires. Ordering it this way costs nothing — the document is cached
        # for its configured TTL.
        metadata = oidc.metadata(resolved)
    except oidc.OidcError as exc:
        logger.warning(
            "Workspace login could not be started for tenant %s: %s",
            tenant.id,
            exc,
        )
        raise LoginRefused from exc

    store.start(
        db,
        tenant_id=tenant.id,
        state=state,
        ceremony=ceremony,
        expires_at=datetime.now(UTC) + timedelta(seconds=resolved.ceremony_ttl_seconds),
    )
    return oidc.authorization_url(
        resolved,
        metadata,
        state=state,
        nonce=ceremony.nonce,
        verifier=ceremony.code_verifier,
    )


def complete_login(
    db: Session,
    *,
    tenant: Tenant,
    state: str,
    code: str,
    store: StateStore = _STORE,
    config: ProviderConfig | None = None,
    request_id: str | None = None,
) -> CompletedLogin:
    """Finish a ceremony, or raise `LoginRefused`.

    The ordering below is the security property, not a style choice:

    1. **consume first.** The ceremony is taken atomically before anything
       expensive happens, so a replayed callback is refused without a round
       trip to the provider — and so a state can never be spent twice even if
       the exchange later fails.
    2. **verify before asking the kernel anything.** `finalize_external_login`
       cannot tell a verified subject from an invented one; it says so, and it
       is right to. Everything it is told has been checked by then.
    3. **finalize and mint in ONE transaction.** The session is added while the
       binding's row lock is still held. `dotmac_kernel.db` commits at the end
       of the request, and that commit releases the lock — so the stamp and the
       session become visible together or not at all.
    """
    resolved = config or provider()

    ceremony = store.consume(db, tenant_id=tenant.id, state=state)
    if ceremony is None:
        logger.warning(
            "Workspace login refused: no live ceremony for the presented state "
            "(tenant %s). Expired, already used, or never started.",
            tenant.id,
        )
        raise LoginRefused

    try:
        verified = oidc.complete_ceremony(
            resolved,
            code=code,
            verifier=ceremony.code_verifier,
            nonce=ceremony.nonce,
        )
    except oidc.OidcError as exc:
        logger.warning(
            "Workspace login refused at the provider exchange (tenant %s): %s",
            tenant.id,
            exc,
        )
        raise LoginRefused from exc

    # The one call that may end in a session. See the module docstring.
    identity = finalize_external_login(
        db,
        tenant=tenant,
        provider_binding=ceremony.provider_binding,
        issuer=verified.issuer,
        subject=verified.subject,
    )
    if identity is None:
        # The subject IS logged, deliberately and only here. An operator
        # cannot create the binding that fixes this without knowing which
        # subject to bind, and this line is where they find it. It never
        # reaches the browser — the refusal the visitor sees says nothing.
        logger.warning(
            "Workspace login refused: issuer %s subject %s is not bound to an "
            "active party in tenant %s at provider binding %r. Bind it "
            "deliberately — there is no automatic provisioning and no email "
            "linking.",
            verified.issuer,
            verified.subject,
            tenant.id,
            ceremony.provider_binding,
        )
        raise LoginRefused

    auth_session, token = session.issue(db, tenant=tenant, party=identity.party)

    write_audit_event(
        db,
        tenant_id=tenant.id,
        actor_party_id=identity.party.id,
        action=LOGIN_SUCCEEDED,
        entity_type="auth_session",
        entity_id=str(auth_session.id),
        request_id=request_id,
        is_success=True,
        details={
            # The provenance the kernel's deferred column will one day hold.
            # Recorded here because the kernel names this as the legitimate
            # interim use, and because a shadow column in this assembly would
            # make it a second writer of session revocation.
            "external_identity_binding_id": str(identity.binding_id),
            "provider_binding": ceremony.provider_binding,
            "issuer": verified.issuer,
        },
    )

    return CompletedLogin(
        party=identity.party,
        token=token,
        expires_at=auth_session.expires_at,
        return_path=ceremony.return_path,
        binding_id=identity.binding_id,
    )


def end_session(
    db: Session,
    *,
    tenant: Tenant,
    party: Party,
    token: str,
    request_id: str | None = None,
) -> None:
    """Revoke this session. Idempotent, and audited when it did something.

    A logout that found nothing to revoke writes no event: an audit trail full
    of "logged out" entries for sessions that had already expired is a trail
    nobody reads.
    """
    revoked = session.revoke(db, tenant=tenant, token=token)
    if revoked is None:
        return
    write_audit_event(
        db,
        tenant_id=tenant.id,
        actor_party_id=party.id,
        action=LOGOUT,
        entity_type="auth_session",
        entity_id=str(revoked.id),
        request_id=request_id,
        is_success=True,
    )


__all__ = [
    "LOGIN_SUCCEEDED",
    "LOGOUT",
    "CompletedLogin",
    "LoginRefused",
    "begin_login",
    "complete_login",
    "end_session",
]
