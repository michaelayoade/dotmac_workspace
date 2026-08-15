"""Ceremony state: opaque, single-use, server-side, and shared between workers.

## What the `state` parameter is here

A random identifier and nothing else. The code verifier, the nonce and the
return path stay in this database; none of them travels through the browser,
the URL, or a cookie. The value the provider echoes back is a lookup key, so
an attacker who obtains it learns nothing and — because consuming it is a
single statement that deletes the row — can use it at most once, and only if
they win a race against the legitimate callback.

That shape is what makes the ceremony resistant to the two attacks a login
redirect invites. Cross-site request forgery on the callback is refused because
only a browser that STARTED a ceremony holds a state that resolves to a row.
Authorization-code injection is refused because the code is redeemed against a
PKCE verifier this row holds and the attacker never saw.

## Why PostgreSQL, and why `DELETE … RETURNING`

A production Workspace runs more than one worker, and a login started on one
must complete on another — the browser goes to the identity provider and comes
back to whichever process the load balancer picks. Any per-process store makes
that a coin flip, and the failure looks like an intermittent, unreproducible
"login sometimes fails" rather than like the design defect it is.

Single-use is likewise not a property a read-then-delete pair can have:

    row = SELECT … WHERE state = :s      -- two callbacks both see it
    DELETE FROM … WHERE state = :s       -- both proceed with the same verifier

`take` is therefore ONE statement:

    DELETE FROM public.workspace_login_states
     WHERE tenant_id = :tenant_id AND state_hash = :state_hash
       AND expires_at > now()
    RETURNING …

Under READ COMMITTED a concurrent `DELETE` re-checks the row it waited on, and
a row another transaction has already removed simply drops out of the result.
So exactly one caller receives a row, whichever order they arrive in, on
whichever worker, without an advisory lock, a queue, or a retry loop. The
property is proven against a real database in
`tests/db/test_state_store_atomicity.py`.

## The stored state is a HASH

`state_hash` is `sha256(state)`, hex. The state is a bearer value for the
duration of one ceremony, so a database dump, a replica, or a stray log of a
query plan should not hand anyone a usable one. Hashing costs a `WHERE` clause
nothing — the lookup is still one indexed equality — and the column is unique
per tenant, so the hash is the key.

## Expiry is enforced in the statement, not by a sweeper

`expires_at > now()` is part of the consuming DELETE, so an expired ceremony is
refused even if nothing has swept it. `start` opportunistically deletes this
tenant's expired rows, which keeps the table small without a scheduled job this
assembly has nowhere to run.

## `InMemoryStateStore`

There isn't one in this package, and that is the point rather than an omission.
A test double that satisfies `StateStore` lives under `tests/support/`, so it
is not part of the built wheel and cannot be selected by configuration,
imported by accident, or reached by any production code path.
`tests/test_state_store_is_shared.py` proves by AST that no such class is
defined or referenced anywhere under `src/`.
"""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Final, Protocol
from uuid import UUID, uuid4

from sqlalchemy import text
from sqlalchemy.orm import Session

#: The assembly's own table, in the host schema. Created by `a001` in this
#: repository's own migration lineage — see `alembic/versions/`. Fully
#: qualified, never relying on `search_path`: that is connection state a pooler
#: or another session can change underneath this one.
CEREMONY_TABLE: Final[str] = "public.workspace_login_states"

# The three statements, written out at module level so a reader sees the SQL
# without assembling it from a method body — and so the `S608` suppressions
# below have one place to be justified rather than three.
#
# Ruff flags an interpolated table name as a possible injection. The
# interpolated value is `CEREMONY_TABLE`, a module constant: no caller supplies
# it, and there is no code path by which a request value reaches it. Every
# value that DOES come from a caller is a bound parameter — `:tenant_id`,
# `:state_hash`, and the rest — which is the property that actually matters and
# is visible in each statement below.

_SWEEP_SQL: Final[str] = (
    f"DELETE FROM {CEREMONY_TABLE} "  # noqa: S608 - constant, see above
    "WHERE tenant_id = :tenant_id AND expires_at <= now()"
)

_INSERT_SQL: Final[str] = (
    f"INSERT INTO {CEREMONY_TABLE} ("  # noqa: S608 - constant, see above
    " id, tenant_id, state_hash, code_verifier, nonce,"
    " redirect_uri, return_to, issued_at, provider_binding, expires_at"
    ") VALUES ("
    " :id, :tenant_id, :state_hash, :code_verifier, :nonce,"
    " :redirect_uri, :return_to, :issued_at, :provider_binding, :expires_at"
    ")"
)

#: The single-use guarantee, in one statement. See the module docstring.
_CONSUME_SQL: Final[str] = (
    f"DELETE FROM {CEREMONY_TABLE} "  # noqa: S608 - constant, see above
    "WHERE tenant_id = :tenant_id "
    "  AND state_hash = :state_hash "
    "  AND expires_at > now() "
    "RETURNING code_verifier, nonce, redirect_uri, return_to, issued_at, "
    "provider_binding"
)


@dataclass(frozen=True, slots=True)
class LoginState:
    """One in-flight login. **Held server-side; never serialized to the wire.**

    Field-for-field the shape `dotmac_auth_oidc.state.LoginState` defines, and
    deliberately so: this assembly is the pilot adopter of that package, and a
    local shape that merely resembled it would have to be translated at the
    seam — which is where a `nonce` and a `return_to` get swapped and nobody
    notices until a login silently completes against the wrong ceremony. When
    the package is published this class is deleted and its import takes its
    place; nothing else in this file changes.

    `code_verifier` is the reason it does not travel: possession of it plus an
    intercepted authorization code completes the exchange, which is precisely
    what PKCE exists to prevent.

    `provider_binding` is NOT here. It is not the protocol's business — it names
    which local registration a ceremony belongs to, so it is the store's column
    and the store's check. See `PostgresStateStore`.
    """

    state_id: str
    nonce: str
    code_verifier: str
    redirect_uri: str
    issued_at: int
    return_to: str = "/"

    def expired(self, *, ttl_seconds: int, now: int | None = None) -> bool:
        clock = int(time.time()) if now is None else now
        return clock - self.issued_at > ttl_seconds


def state_hash(state: str) -> str:
    """`sha256(state)`, hex — what the table actually stores."""
    return hashlib.sha256(state.encode("utf-8")).hexdigest()


class StateStore(Protocol):
    """Hold a ceremony, and take it back exactly once.

    `put`/`take` rather than `start`/`consume`, and with no `db` or `tenant_id`
    parameter: this is `dotmac_auth_oidc.state.StateStore` exactly, so the
    adapter below satisfies the package structurally with no base class and no
    translation layer.

    The request's session and tenant are held by the INSTANCE instead — see
    `PostgresStateStore.__init__` for why that is the only shape a
    database-backed store can honestly have.

    There is deliberately no `get`: a reader that could look without consuming
    is the read-then-delete pair this store exists to make unavailable.
    """

    def put(self, state: LoginState, *, ttl_seconds: int) -> None:
        """Hold `state` for at most `ttl_seconds`. Raises on a duplicate state
        id, which cannot happen with a 256-bit random and would mean the
        generator is broken."""
        ...

    def take(self, state_id: str) -> LoginState | None:
        """Take the ceremony, atomically and once. `None` if there is none, it
        belongs to another tenant, it has expired, or it was already used — all
        four indistinguishable to the caller, on purpose."""
        ...


class PostgresStateStore:
    """The shared, atomic store. The only one this assembly composes.

    Constructed PER REQUEST, holding that request's `Session`. That is not a
    convenience: `dotmac_kernel.db` owns when a transaction opens and commits
    (hard rule 8), so a store that held a long-lived session would be a second
    transaction authority — the ceremony would commit at a different moment
    from everything else the request did, and a rolled-back request would leave
    a live ceremony behind. It is also why the OIDC client cannot hold this
    store for the life of the process, and why the package accepts one per
    ceremony operation instead.

    `provider_binding` is held here rather than in `LoginState` because it is
    this deployment's vocabulary, not the protocol's. It is written with the
    ceremony and CHECKED on the way out: a ceremony started against one
    registration cannot be completed against another, so a configuration change
    mid-flight refuses rather than finishing a login against an issuer the
    member never authenticated to.
    """

    __slots__ = ("_binding", "_db", "_tenant_id")

    def __init__(self, db: Session, *, tenant_id: UUID, provider_binding: str) -> None:
        self._db = db
        self._tenant_id = tenant_id
        self._binding = provider_binding

    def put(self, state: LoginState, *, ttl_seconds: int) -> None:
        # Opportunistic housekeeping, scoped to this tenant and bounded by the
        # same index the consume path uses. Cheap enough to run on the way in,
        # which is what lets this table live without a scheduled sweeper.
        self._db.execute(text(_SWEEP_SQL), {"tenant_id": str(self._tenant_id)})
        self._db.execute(
            text(_INSERT_SQL),
            {
                "id": str(uuid4()),
                "tenant_id": str(self._tenant_id),
                "state_hash": state_hash(state.state_id),
                "code_verifier": state.code_verifier,
                "nonce": state.nonce,
                "redirect_uri": state.redirect_uri,
                "return_to": state.return_to,
                "issued_at": state.issued_at,
                "provider_binding": self._binding,
                "expires_at": datetime.now(UTC) + timedelta(seconds=ttl_seconds),
            },
        )

    def take(self, state_id: str) -> LoginState | None:
        """One statement. See the module docstring for why that is the whole
        single-use guarantee, and why a `SELECT` followed by a `DELETE` is not.

        `tenant_id` is in the predicate as well as in the RLS policy. The
        policy is what enforces isolation; this is the belt to its braces, and
        it also keeps the statement correct when it is exercised through a
        migration-role connection that bypasses RLS.
        """
        row = (
            self._db.execute(
                text(_CONSUME_SQL),
                {
                    "tenant_id": str(self._tenant_id),
                    "state_hash": state_hash(state_id),
                },
            )
            .mappings()
            .first()
        )
        if row is None:
            return None
        if row["provider_binding"] != self._binding:
            # The ceremony IS consumed — the row is gone by the time this is
            # read, and that is correct: a ceremony nobody can complete must
            # not linger. What is refused is completing it against a different
            # registration than the one the member authenticated to.
            return None
        return LoginState(
            state_id=state_id,
            nonce=row["nonce"],
            code_verifier=row["code_verifier"],
            redirect_uri=row["redirect_uri"],
            issued_at=row["issued_at"],
            return_to=row["return_to"],
        )


__all__ = [
    "CEREMONY_TABLE",
    "LoginState",
    "PostgresStateStore",
    "StateStore",
    "state_hash",
]
