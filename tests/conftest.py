"""Make the kernel importable without a database, and hold the test doubles.

## Why `DATABASE_URL` is set here

`dotmac_kernel.db` builds its SQLAlchemy engines at IMPORT time, from
`settings.database_url` — and `create_engine("")` raises rather than deferring,
so `import dotmac_kernel.deps` fails outright when `DATABASE_URL` is unset. Every
test in this repository imports the launcher, which imports `deps`, so without
this the suite could not even collect.

The URL below is deliberately unreachable and deliberately syntactically valid.
An engine is lazy about CONNECTING, so a parseable URL is all an import needs,
and a parseable-but-dead one means a test that accidentally opens a connection
fails loudly instead of finding something real. `setdefault`, so a run that
supplies a genuine URL (the `tests/db` canaries) keeps it.

This is the whole reason nothing outside `tests/db` may touch a database: the
static suite is about structure and refusals, and the tenancy properties are
only true against a real, migrated PostgreSQL with RLS.

## Why the in-memory state store lives HERE and not in the package

A per-process ceremony store is wrong in production for a reason that does not
announce itself: a login starts on one worker and finishes on another, so a
Workspace behind more than one process would complete a login only when the
load balancer happened to pick the same worker twice. The failure is
intermittent, unreproducible, and looks like flakiness rather than like a
design defect.

Shipping such a class and then guarding against SELECTING it would put the
wrong answer one configuration value away from a production deployment. Keeping
it in `conftest.py` puts it outside the wheel entirely: there is nothing to
select, nothing to import by accident, and no environment variable that could
reach it. `tests/test_state_store_is_shared.py` enforces the "not in `src/`"
half by AST, and it is delivered as a FIXTURE rather than an importable module
so that no test needs a `sys.path` assumption to reach it.

It is also not a lesser implementation of the same contract, and cannot be: the
single-use guarantee in `PostgresStateStore` is a property of one SQL statement
under READ COMMITTED, and the nearest single-threaded analogue is the
dictionary `pop` below. That is enough for the flow tests that need somewhere
to put a ceremony; it is not evidence of the property, which is proven against
a real PostgreSQL in `tests/db/test_state_store_atomicity.py`.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime
from uuid import UUID

import pytest

os.environ.setdefault(
    "DATABASE_URL", "postgresql+psycopg://unused:unused@127.0.0.1:1/unused"
)

# Imported AFTER the URL above is set — see the first section of this docstring.
from dotmac_workspace.identity.state_store import (
    LoginCeremony,
    state_hash,
)


class InMemoryStateStore:
    """Satisfies `StateStore`. Never reachable from `src/`."""

    def __init__(self) -> None:
        self._rows: dict[tuple[str, str], tuple[LoginCeremony, datetime]] = {}

    def start(
        self,
        db: object,
        *,
        tenant_id: UUID,
        state: str,
        ceremony: LoginCeremony,
        expires_at: datetime,
    ) -> None:
        self._rows[(str(tenant_id), state_hash(state))] = (ceremony, expires_at)

    def consume(
        self, db: object, *, tenant_id: UUID, state: str
    ) -> LoginCeremony | None:
        """`pop` — the nearest single-threaded analogue of `DELETE … RETURNING`.

        Expiry is checked here for the same reason the SQL checks it in the
        statement: a ceremony that has run out of time must be refused whether
        or not anything has swept it.
        """
        found = self._rows.pop((str(tenant_id), state_hash(state)), None)
        if found is None:
            return None
        ceremony, expires_at = found
        if expires_at <= datetime.now(UTC):
            return None
        return ceremony

    def __len__(self) -> int:
        return len(self._rows)


@pytest.fixture
def store() -> InMemoryStateStore:
    """A fresh ceremony store per test — state must never leak between them."""
    return InMemoryStateStore()
