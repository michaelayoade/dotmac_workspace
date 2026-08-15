"""Make the kernel importable without a database.

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
"""

from __future__ import annotations

import os

os.environ.setdefault(
    "DATABASE_URL", "postgresql+psycopg://unused:unused@127.0.0.1:1/unused"
)
