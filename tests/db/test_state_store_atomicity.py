"""A login ceremony is consumed exactly once, under real concurrency.

## Why this cannot be a unit test

`PostgresStateStore.consume` is one statement:

    DELETE FROM public.workspace_login_states
     WHERE tenant_id = :tenant_id AND state_hash = :state_hash
       AND expires_at > now()
    RETURNING …

Single-use is a property of what PostgreSQL does when two transactions issue
that statement against the same row under READ COMMITTED: one takes the row
lock, the other waits, and when the first commits the second re-evaluates and
finds nothing to delete. No amount of Python can demonstrate that. So this
module runs it, against a real database, from two threads.

## The canary's shape, and why every line of it is deliberate

A previous canary elsewhere in this programme deadlocked and burned twelve
hours of CI. The shape below is copied from what was learned, not invented:

* **Two threads, each with its OWN connection.** Two sessions on one connection
  would serialize in the driver and prove nothing.
* **A `threading.Barrier` AFTER both advisory reads.** Both workers reach the
  same point — each having already seen the row — before either tries to
  consume it. Without the rendezvous the first thread usually finishes before
  the second starts, and the test passes without ever creating the race.
* **Every wait is bounded.** `SET LOCAL lock_timeout` and `SET LOCAL
  statement_timeout` inside each transaction, a timeout on `Barrier.wait`, and
  a timeout on `Future.result`. A canary that can hang is a canary that takes
  a CI runner with it.
* **Workers RETURN outcomes; the test asserts on the collected results.** An
  assertion inside a worker thread fails that thread, not the test — pytest
  never sees it, and the run goes green while the thread dies quietly.
* **The probe is the PROPERTY, not a proxy.** It asserts that exactly one
  worker received a ceremony, not that a particular worker won. Which one wins
  is scheduling; that only one CAN win is the guarantee.

## `SET LOCAL app.current_tenant` is TRANSACTION-local

Both workers set it inside the transaction that consumes, because a `commit()`
discards it. The fixtures below arrange rows in their own short-lived
superuser sessions for the same reason: a fixture that set the scope and then
committed would leave the next statement running with no tenant context, and
under FORCE RLS that fails closed and looks like the store losing rows.
"""

from __future__ import annotations

import hashlib
import threading
import uuid
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass

import pytest
from sqlalchemy import Engine, text

#: Bounds. Generous enough that a slow CI runner is not a false failure, tight
#: enough that a genuine hang fails the job in under a minute instead of at the
#: workflow's own timeout.
LOCK_TIMEOUT = "5s"
STATEMENT_TIMEOUT = "15s"
BARRIER_TIMEOUT_SECONDS = 20.0
RESULT_TIMEOUT_SECONDS = 45.0

CONSUME_SQL = (
    "DELETE FROM public.workspace_login_states "
    "WHERE tenant_id = :tenant_id "
    "  AND state_hash = :state_hash "
    "  AND expires_at > now() "
    "RETURNING code_verifier, nonce, return_path, provider_binding"
)


@dataclass(frozen=True)
class Outcome:
    """What one worker saw. Returned, never asserted on inside the thread."""

    worker: str
    consumed: bool
    verifier: str | None
    error: str | None


def _state_hash(state: str) -> str:
    return hashlib.sha256(state.encode("utf-8")).hexdigest()


@pytest.fixture
def ceremony(admin_engine: Engine) -> Iterator[tuple[str, str, str]]:
    """One tenant with one live ceremony. Yields `(tenant_id, state, verifier)`.

    Arranged with raw SQL as a superuser, so nothing about the arrangement can
    be doing the isolating or the serializing that is under test. Each step is
    its own short-lived transaction.
    """
    tenant_id = str(uuid.uuid4())
    state = f"state-{uuid.uuid4()}"
    verifier = f"verifier-{uuid.uuid4()}"
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO public.tenants (id, slug, name) "
                "VALUES (:id, :slug, :name)"
            ),
            {
                "id": tenant_id,
                "slug": f"ceremony-{tenant_id[:8]}",
                "name": "Ceremony canary",
            },
        )
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO public.workspace_login_states ("
                " id, tenant_id, state_hash, code_verifier, nonce,"
                " return_path, provider_binding, expires_at"
                ") VALUES ("
                " :id, :tenant_id, :state_hash, :verifier, :nonce,"
                " :return_path, :binding, now() + interval '10 minutes'"
                ")"
            ),
            {
                "id": str(uuid.uuid4()),
                "tenant_id": tenant_id,
                "state_hash": _state_hash(state),
                "verifier": verifier,
                "nonce": "nonce-value",
                "return_path": "/applications",
                "binding": "primary",
            },
        )
    yield tenant_id, state, verifier
    with admin_engine.begin() as conn:
        # `ON DELETE CASCADE` from the tenant FK removes the ceremony rows.
        conn.execute(
            text("DELETE FROM public.tenants WHERE id = :id"), {"id": tenant_id}
        )


def _consume_after_barrier(
    engine: Engine,
    *,
    worker: str,
    tenant_id: str,
    state: str,
    barrier: threading.Barrier,
) -> Outcome:
    """One worker: read, rendezvous, consume, report. Never asserts."""
    try:
        with engine.connect() as conn, conn.begin():
            # Transaction-local, every one of them. The tenant scope is
            # discarded by a commit, and the two timeouts must apply to THIS
            # transaction rather than to the connection's whole life.
            conn.execute(
                text("SELECT set_config('app.current_tenant', :tenant_id, true)"),
                {"tenant_id": tenant_id},
            )
            conn.execute(text(f"SET LOCAL lock_timeout = '{LOCK_TIMEOUT}'"))
            conn.execute(text(f"SET LOCAL statement_timeout = '{STATEMENT_TIMEOUT}'"))

            # The advisory read: both workers see the row before either tries
            # to take it. This is what makes the race real rather than
            # theoretical.
            seen = conn.execute(
                text(
                    "SELECT 1 FROM public.workspace_login_states "
                    "WHERE tenant_id = :tenant_id AND state_hash = :state_hash"
                ),
                {"tenant_id": tenant_id, "state_hash": _state_hash(state)},
            ).first()
            if seen is None:
                return Outcome(worker, False, None, "the ceremony was not visible")

            barrier.wait(timeout=BARRIER_TIMEOUT_SECONDS)

            row = (
                conn.execute(
                    text(CONSUME_SQL),
                    {"tenant_id": tenant_id, "state_hash": _state_hash(state)},
                )
                .mappings()
                .first()
            )
            if row is None:
                return Outcome(worker, False, None, None)
            return Outcome(worker, True, row["code_verifier"], None)
    # Broad on purpose: a worker must never raise. An exception escaping a
    # thread fails that thread, not the test — pytest never sees it, and the
    # run goes green while the thread dies quietly. Every failure comes back
    # as an outcome the test asserts on.
    except Exception as exc:
        return Outcome(worker, False, None, f"{type(exc).__name__}: {exc}")


def test_exactly_one_of_two_concurrent_callbacks_consumes_the_ceremony(
    app_engine: Engine, ceremony: tuple[str, str, str]
) -> None:
    """The property, probed directly.

    Not "the first caller wins" — which one wins is scheduling. The guarantee
    is that only one CAN, so that two callbacks presenting the same state can
    never both proceed with the same PKCE verifier.
    """
    tenant_id, state, verifier = ceremony
    barrier = threading.Barrier(2)

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [
            pool.submit(
                _consume_after_barrier,
                app_engine,
                worker=name,
                tenant_id=tenant_id,
                state=state,
                barrier=barrier,
            )
            for name in ("left", "right")
        ]
        outcomes = [future.result(timeout=RESULT_TIMEOUT_SECONDS) for future in futures]

    errors = [outcome for outcome in outcomes if outcome.error]
    assert not errors, f"a worker failed rather than losing the race: {errors}"

    consumed = [outcome for outcome in outcomes if outcome.consumed]
    assert len(consumed) == 1, (
        f"{len(consumed)} of 2 concurrent callbacks consumed the same ceremony "
        f"({outcomes}). Single-use is what stops two callbacks proceeding with "
        "one PKCE verifier; it is a property of the single DELETE … RETURNING, "
        "and a SELECT-then-DELETE would produce exactly this failure."
    )
    assert (
        consumed[0].verifier == verifier
    ), "the winner received a different ceremony than the one seeded"


def test_the_ceremony_is_gone_afterwards(
    app_engine: Engine, admin_engine: Engine, ceremony: tuple[str, str, str]
) -> None:
    """Consuming deletes. A store that only marked a row used would let a
    second callback find it, and the mark would have to be checked by every
    reader forever."""
    tenant_id, state, _ = ceremony
    with app_engine.connect() as conn, conn.begin():
        conn.execute(
            text("SELECT set_config('app.current_tenant', :tenant_id, true)"),
            {"tenant_id": tenant_id},
        )
        conn.execute(text(f"SET LOCAL lock_timeout = '{LOCK_TIMEOUT}'"))
        conn.execute(text(f"SET LOCAL statement_timeout = '{STATEMENT_TIMEOUT}'"))
        first = (
            conn.execute(
                text(CONSUME_SQL),
                {"tenant_id": tenant_id, "state_hash": _state_hash(state)},
            )
            .mappings()
            .first()
        )
    assert first is not None

    with admin_engine.connect() as conn:
        remaining = conn.execute(
            text(
                "SELECT count(*) FROM public.workspace_login_states "
                "WHERE tenant_id = :tenant_id AND state_hash = :state_hash"
            ),
            {"tenant_id": tenant_id, "state_hash": _state_hash(state)},
        ).scalar()
    assert remaining == 0


def test_an_expired_ceremony_is_refused_by_the_statement_itself(
    app_engine: Engine, admin_engine: Engine, ceremony: tuple[str, str, str]
) -> None:
    """Expiry is in the consuming DELETE, so it holds whether or not anything
    has swept the table. A sweeper that had not run yet would otherwise make an
    expired ceremony usable."""
    tenant_id, state, _ = ceremony
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "UPDATE public.workspace_login_states "
                "SET expires_at = now() - interval '1 second' "
                "WHERE tenant_id = :tenant_id AND state_hash = :state_hash"
            ),
            {"tenant_id": tenant_id, "state_hash": _state_hash(state)},
        )

    with app_engine.connect() as conn, conn.begin():
        conn.execute(
            text("SELECT set_config('app.current_tenant', :tenant_id, true)"),
            {"tenant_id": tenant_id},
        )
        conn.execute(text(f"SET LOCAL statement_timeout = '{STATEMENT_TIMEOUT}'"))
        row = (
            conn.execute(
                text(CONSUME_SQL),
                {"tenant_id": tenant_id, "state_hash": _state_hash(state)},
            )
            .mappings()
            .first()
        )
    assert row is None
