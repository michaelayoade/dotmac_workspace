"""The login flow — the Workspace's own, start to finish.

`web.py` validates and delegates; the decisions are here (AGENTS.md §5).

## The whole flow, and where each guarantee comes from

    POST /login          begin_login   -> opaque state stored AND cookied,
                                          browser sent away
    GET  /login/callback complete_login-> state pair matched, ceremony taken
                                          ID token verified, binding finalized,
                                          session minted in the SAME transaction
    POST /logout         end_session   -> session revoked, cookie cleared

| guarantee | who provides it |
|---|---|
| this browser is the one that started | the state pair: query vs cookie |
| an intercepted authorization code is useless | PKCE S256, `oidc` |
| the ID token belongs to THIS ceremony | `nonce`, `oidc` |
| a ceremony is used at most once, on any worker | `DELETE … RETURNING` |
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
import time
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from secrets import compare_digest
from uuid import UUID

from dotmac_kernel.audit import write_audit_event
from dotmac_kernel.external_identity import finalize_external_login
from dotmac_kernel.models import Party, Tenant
from sqlalchemy.orm import Session

from dotmac_workspace.identity import oidc, session
from dotmac_workspace.identity.config import ProviderConfig, provider
from dotmac_workspace.identity.state_store import (
    LoginState,
    PostgresStateStore,
    StateStore,
)

logger = logging.getLogger(__name__)

#: Declared by this feature's manifest, and written from here. Both have a real
#: consumer in the same change that declares them (ADR-0008).
LOGIN_SUCCEEDED = "workspace.login.succeeded"
LOGOUT = "workspace.logout"


def _request_store(db: Session, *, tenant: Tenant, provider_binding: str) -> StateStore:
    """The shared, atomic store, bound to THIS request.

    Built per call rather than held as a module singleton, because it holds the
    request's `Session`. `dotmac_kernel.db` owns when a transaction opens and
    commits (hard rule 8), so a store that held a session of its own would be a
    second transaction authority: the ceremony would commit at a different
    moment from everything else the request did, and a rolled-back request
    would leave a live ceremony behind.

    There is deliberately no configuration knob. Which store a production
    process uses is the one thing that must never be selectable — a per-worker
    store one environment variable away is how a login becomes a coin flip.
    The `store` parameter below exists for tests, and there is no in-memory
    implementation anywhere under `src/` for it to reach.
    """
    return PostgresStateStore(
        db, tenant_id=tenant.id, provider_binding=provider_binding
    )


class LoginRefused(Exception):
    """The ceremony did not produce a session. One type, no reason field."""


@dataclass(frozen=True, slots=True)
class StartedLogin:
    """Where to send the browser, and the value that must come back on it.

    `state` is returned so the ADAPTER can set it as a host-only cookie. The
    query parameter alone proves a ceremony exists; only a value the attacker
    cannot write onto the victim's browser proves that THIS browser started it.
    See `tests/test_login_csrf.py`.
    """

    url: str
    state: str
    #: When the ceremony row stops being valid. The cookie is given the same
    #: lifetime, so the browser forgets it instead of holding a dead value.
    expires_at: datetime


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
    store: StateStore | None = None,
    config: ProviderConfig | None = None,
) -> StartedLogin:
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
    ceremony = LoginState(
        state_id=oidc.new_state(),
        nonce=oidc.new_nonce(),
        code_verifier=oidc.new_code_verifier(),
        redirect_uri=resolved.redirect_url,
        issued_at=int(time.time()),
        return_to=return_path,
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

    ttl = resolved.ceremony_ttl_seconds
    # `is not None`, never `store or ...`: a store is an object with a
    # `__len__`, so an EMPTY one is falsy and the truthiness form silently
    # replaces it with a real database store. CI caught exactly that.
    ceremony_store = (
        store
        if store is not None
        else _request_store(
            db, tenant=tenant, provider_binding=resolved.provider_binding
        )
    )
    ceremony_store.put(ceremony, ttl_seconds=ttl)
    return StartedLogin(
        url=oidc.authorization_url(
            resolved,
            metadata,
            state=ceremony.state_id,
            nonce=ceremony.nonce,
            verifier=ceremony.code_verifier,
        ),
        state=ceremony.state_id,
        expires_at=datetime.now(UTC) + timedelta(seconds=ttl),
    )


def complete_login(
    db: Session,
    *,
    tenant: Tenant,
    state: str,
    stored_state: str | None,
    code: str,
    store: StateStore | None = None,
    config: ProviderConfig | None = None,
    request_id: str | None = None,
) -> CompletedLogin:
    """Finish a ceremony, or raise `LoginRefused`.

    `state` is the query parameter the provider echoed; `stored_state` is the
    host-only cookie this deployment set when the ceremony started. BOTH are
    required and they must match.

    That pair is the whole defence against login CSRF, and it is not
    interchangeable with the checks below. An attacker can authenticate
    honestly as themselves, obtain a perfectly valid `code` and `state`, and
    send that callback URL to a victim; the victim's browser opens it and
    Workspace mints a session for the ATTACKER on the VICTIM's browser. PKCE
    does not help — the verifier never left this server, so the exchange
    succeeds. Nor does the state alone: resolving to a stored ceremony proves
    the ceremony EXISTS, not that this browser started it. Only a value the
    attacker cannot write onto the victim's browser proves that.

    Checked FIRST, before the ceremony is consumed, so a forged callback cannot
    burn a ceremony that belongs to somebody else — see
    `tests/test_login_csrf.py` for why that ordering is deliberate.

    The ordering below is the security property, not a style choice:

    0. **bind to the browser.** Query state and cookie state must match.
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

    if not state or not stored_state or not compare_digest(state, stored_state):
        logger.warning(
            "Workspace login refused for tenant %s: the callback state does not "
            "match the browser's ceremony cookie",
            tenant.id,
        )
        raise LoginRefused

    ceremony_store = (
        store
        if store is not None
        else _request_store(
            db, tenant=tenant, provider_binding=resolved.provider_binding
        )
    )
    ceremony = ceremony_store.take(state)
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
        provider_binding=resolved.provider_binding,
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
            resolved.provider_binding,
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
            "provider_binding": resolved.provider_binding,
            "issuer": verified.issuer,
        },
    )

    return CompletedLogin(
        party=identity.party,
        token=token,
        expires_at=auth_session.expires_at,
        return_path=ceremony.return_to,
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
