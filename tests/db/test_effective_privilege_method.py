"""The replacement is the REASON, and this is where that is observed.

A test showing only that `has_table_privilege` refuses a planted reach proves
the new method works. A test showing only that
`information_schema.table_privileges` misses it proves the old method was
broken. Neither, alone, shows that swapping one for the other is what fixed
`tests/db/test_login_state_isolation.py` — so every case below observes **both
halves against the same planted reach**, in the same transaction, and asserts
them together.

Three reaches are planted, one for each way the discredited form goes green
over a live path — the membership case Governance ADR 0022 § 3 property 9 names,
and the two narrowings § 3 explicitly refuses:

1. **Through a role MEMBERSHIP.** The role holds nothing directly and can read
   the table. This is the case Workspace's own restore drill had already
   proven possible from the other side — a membership present while the
   privilege is not effective — so the distinction was known here before the
   tests failed to apply it.
2. **Through a COLUMN grant.** `has_table_privilege` is false while the column
   is readable, which is why `has_any_column_privilege` is named separately.
3. **Through a privilege that is not `SELECT`.** A `TRUNCATE`-only reach empties
   the table without ever reading a row, and a `SELECT`-only check reports
   isolation over it.

Every planted reach is also EXERCISED under `SET LOCAL ROLE`, so the claim does
not rest on what a catalog function says: the role really can touch the table.

**Nothing here plants anything on a Workspace table.** The scratch schema, its
one table and the probe roles exist only inside this module's fixture and are
dropped by it. The ACLs of `public.workspace_login_states` and
`mod_appdir.application_bindings` are never modified — a sensitivity proof that
mutated the object under test would be arranging the answer it then reports.
That is also why this is a detector proof and not a rehearsal harness: ADR 0022
§ 6 forbids a RESTORE rehearsal from issuing `CREATE ROLE` or `GRANT` against
the instance it is validating, because a validator must not supply what the
backup should carry. This fixture supplies a violation for the detector to find,
against objects no property is claimed about.

Statements are literals throughout, with fixed identifiers, because an
identifier cannot be a bound parameter and a security canary is the wrong place
to leave an interpolated name behind.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterator

import pytest
from sqlalchemy import Engine, text
from sqlalchemy.exc import DBAPIError

from effective_privileges import (
    TABLE_PRIVILEGES,
    direct_grant_listing,
    effective_privileges,
    table_level_privileges_only,
)

PROBE_SCHEMA = "ws_privilege_probe"
PROBE_TABLE = "planted"

#: Holds all seven privileges DIRECTLY. Never asserted about; it exists to be
#: the thing a membership reaches through.
GRANTEE = "ws_probe_grantee"
#: Holds NOTHING directly and is a member of `GRANTEE`. The whole point.
VIA_MEMBERSHIP = "ws_probe_member"
#: Holds a single COLUMN grant, directly. No table-level privilege at all.
VIA_COLUMN = "ws_probe_column"
#: Holds `TRUNCATE` only, and only through a membership.
TRUNCATE_GRANTEE = "ws_probe_truncate_grantee"
VIA_TRUNCATE = "ws_probe_truncate_member"

_PROBE_ROLES = (
    GRANTEE,
    VIA_MEMBERSHIP,
    VIA_COLUMN,
    TRUNCATE_GRANTEE,
    VIA_TRUNCATE,
)

# Teardown, run BEFORE setup as well: a previous run that died between CREATE
# and DROP would otherwise poison every later one, and roles are CLUSTER-level
# so dropping the schema does not reach them. The schema goes first, which takes
# every grant on it away — that is what lets the roles drop cleanly, and a
# leftover dependency therefore fails LOUDLY here instead of being swallowed.
_DROP_PROBE: tuple[str, ...] = (
    "DROP SCHEMA IF EXISTS ws_privilege_probe CASCADE;",
    "DROP ROLE IF EXISTS ws_probe_member;",
    "DROP ROLE IF EXISTS ws_probe_grantee;",
    "DROP ROLE IF EXISTS ws_probe_column;",
    "DROP ROLE IF EXISTS ws_probe_truncate_member;",
    "DROP ROLE IF EXISTS ws_probe_truncate_grantee;",
)

_CREATE_PROBE: tuple[str, ...] = (
    "CREATE SCHEMA ws_privilege_probe;",
    (
        "CREATE TABLE ws_privilege_probe.planted "
        "(id uuid PRIMARY KEY, secret text NOT NULL);"
    ),
    "CREATE ROLE ws_probe_grantee NOLOGIN;",
    "CREATE ROLE ws_probe_member NOLOGIN INHERIT;",
    "CREATE ROLE ws_probe_column NOLOGIN INHERIT;",
    "CREATE ROLE ws_probe_truncate_grantee NOLOGIN;",
    "CREATE ROLE ws_probe_truncate_member NOLOGIN INHERIT;",
    # PostgreSQL 16 fixes a membership's INHERIT at GRANT time from the
    # grantee's then-current setting, so `WITH INHERIT TRUE` is STATED rather
    # than assumed: a membership granted while the role was NOINHERIT stays
    # non-inheriting even after `ALTER ROLE … INHERIT` — `rolinherit = t`,
    # membership present, `has_table_privilege` still false. The planted reach
    # would silently not exist, and a sensitivity proof would prove nothing.
    "GRANT ws_probe_grantee TO ws_probe_member WITH INHERIT TRUE;",
    (
        "GRANT ws_probe_truncate_grantee TO ws_probe_truncate_member "
        "WITH INHERIT TRUE;"
    ),
    (
        "GRANT USAGE ON SCHEMA ws_privilege_probe TO ws_probe_grantee, "
        "ws_probe_member, ws_probe_column, ws_probe_truncate_grantee, "
        "ws_probe_truncate_member;"
    ),
    # Case 1: every privilege, held directly by the role the member inherits
    # from. The member itself is granted nothing at all.
    (
        "GRANT SELECT, INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER "
        "ON ws_privilege_probe.planted TO ws_probe_grantee;"
    ),
    # Case 2: one column, granted directly. No table-level privilege follows.
    "GRANT SELECT (secret) ON ws_privilege_probe.planted TO ws_probe_column;",
    # Case 3: a privilege that reads nothing, reached through a membership.
    "GRANT TRUNCATE ON ws_privilege_probe.planted TO ws_probe_truncate_grantee;",
)


@pytest.fixture(scope="module")
def planted_reach(admin_engine: Engine) -> Iterator[None]:
    """A scratch schema, one table, and five roles that reach it three ways.

    Module-scoped: the planted state is read-only for every test below, and
    creating cluster-level roles once keeps the proof from depending on the
    order tests happen to run in.
    """
    with admin_engine.begin() as conn:
        for statement in (*_DROP_PROBE, *_CREATE_PROBE):
            conn.execute(text(statement))
        conn.execute(
            text(
                "INSERT INTO ws_privilege_probe.planted (id, secret) "
                "VALUES (:id, 'a value only a reachable role can read')"
            ),
            {"id": str(uuid.uuid4())},
        )
    yield
    with admin_engine.begin() as conn:
        for statement in _DROP_PROBE:
            conn.execute(text(statement))


def _read_the_planted_row_as(engine: Engine, statement: str, role: str) -> None:
    """Run `statement` with the session's role set to `role`, then roll back.

    `SET LOCAL ROLE` is transaction-scoped, so the connection returns to the
    pool as itself even if the statement raises. The transaction is always
    rolled back: TRUNCATE is one of the statements below.
    """
    with engine.connect() as conn:
        conn.begin()
        conn.execute(text("SET LOCAL statement_timeout = '15s'"))
        conn.execute(text(f"SET LOCAL ROLE {role}"))
        try:
            conn.execute(text(statement))
        finally:
            conn.rollback()


def test_a_membership_only_reach_is_missed_by_the_listing_and_refused_by_the_check(
    admin_engine: Engine, planted_reach: None
) -> None:
    """The acceptance criterion, both halves against one planted reach.

    `ws_probe_member` holds not one privilege of its own. It is a member of a
    role that holds all seven, and PostgreSQL resolves that membership for it —
    so it can read, write, empty and attach triggers to the table.
    """
    with admin_engine.connect() as conn:
        listed = direct_grant_listing(
            conn, role=VIA_MEMBERSHIP, schema=PROBE_SCHEMA, table=PROBE_TABLE
        )
        effective = effective_privileges(
            conn, role=VIA_MEMBERSHIP, schema=PROBE_SCHEMA, table=PROBE_TABLE
        )

    # Half one — the discredited method MISSES it. Not "reports less"; reports
    # nothing at all, which an isolation assertion reads as proof of isolation.
    assert listed == frozenset(), (
        "the direct-grant listing has stopped being blind to a membership. "
        "This half of the proof no longer demonstrates the defect the "
        "replacement exists to fix — do not delete it; work out what changed."
    )

    # Half two — the replacement REFUSES it, and names every privilege.
    assert effective == frozenset(TABLE_PRIVILEGES), (
        "the effective-privilege check missed a reach that PostgreSQL grants: "
        f"saw {sorted(effective)}, expected all seven"
    )

    # And the reach is real, not merely what a catalog function reports.
    _read_the_planted_row_as(
        admin_engine, "SELECT secret FROM ws_privilege_probe.planted", VIA_MEMBERSHIP
    )
    _read_the_planted_row_as(
        admin_engine, "TRUNCATE ws_privilege_probe.planted", VIA_MEMBERSHIP
    )


def test_a_column_only_reach_is_missed_by_the_listing_and_by_table_granularity(
    admin_engine: Engine, planted_reach: None
) -> None:
    """The narrowing ADR 0022 § 3 refuses second: table granularity alone.

    `ws_probe_column` can read `secret` and nothing else. The listing shows
    nothing, `has_table_privilege` is false, and the column is readable — three
    statements that are all true at once, which is the whole problem.
    """
    with admin_engine.connect() as conn:
        listed = direct_grant_listing(
            conn, role=VIA_COLUMN, schema=PROBE_SCHEMA, table=PROBE_TABLE
        )
        table_only = table_level_privileges_only(
            conn, role=VIA_COLUMN, schema=PROBE_SCHEMA, table=PROBE_TABLE
        )
        effective = effective_privileges(
            conn, role=VIA_COLUMN, schema=PROBE_SCHEMA, table=PROBE_TABLE
        )

    assert listed == frozenset(), (
        "a column grant has started appearing in table_privileges; this half "
        "of the proof no longer demonstrates the defect"
    )
    assert table_only == frozenset(), (
        "has_table_privilege has started answering a column grant; the second "
        "narrowing this test exists for is no longer demonstrable here"
    )
    assert effective == frozenset(
        {"SELECT"}
    ), f"the effective check missed a readable column: saw {sorted(effective)}"

    _read_the_planted_row_as(
        admin_engine, "SELECT secret FROM ws_privilege_probe.planted", VIA_COLUMN
    )
    # …and only that column. The grant is narrow, so the proof should be too.
    with pytest.raises(DBAPIError):
        _read_the_planted_row_as(
            admin_engine, "SELECT id FROM ws_privilege_probe.planted", VIA_COLUMN
        )


def test_a_truncate_only_reach_is_invisible_to_a_select_only_question(
    admin_engine: Engine, planted_reach: None
) -> None:
    """The narrowing ADR 0022 § 3 refuses first: `SELECT` alone is not the
    property.

    `ws_probe_truncate_member` cannot read one row and can empty the table. A
    check that asked only about `SELECT` would report it isolated.
    """
    with admin_engine.connect() as conn:
        listed = direct_grant_listing(
            conn, role=VIA_TRUNCATE, schema=PROBE_SCHEMA, table=PROBE_TABLE
        )
        effective = effective_privileges(
            conn, role=VIA_TRUNCATE, schema=PROBE_SCHEMA, table=PROBE_TABLE
        )

    assert (
        listed == frozenset()
    ), "the direct-grant listing has stopped being blind to this membership"
    assert "SELECT" not in effective, (
        "the planted role can read the table, so this case no longer shows "
        "what a SELECT-only check would miss"
    )
    assert effective == frozenset(
        {"TRUNCATE"}
    ), f"the effective check missed a TRUNCATE-only reach: saw {sorted(effective)}"

    with pytest.raises(DBAPIError):
        _read_the_planted_row_as(
            admin_engine,
            "SELECT secret FROM ws_privilege_probe.planted",
            VIA_TRUNCATE,
        )
    _read_the_planted_row_as(
        admin_engine, "TRUNCATE ws_privilege_probe.planted", VIA_TRUNCATE
    )


def test_the_probe_never_touched_a_workspace_table(
    admin_engine: Engine, planted_reach: None
) -> None:
    """The fixture's blast radius, asserted rather than promised.

    A sensitivity proof that granted a probe role something on a real table
    would leave the next isolation assertion measuring this module's fixture
    instead of the product. Takes `planted_reach` so the roles certainly
    exist while the question is asked — a version that skipped absent roles
    would pass loudest exactly when the fixture had failed to run.
    """
    with admin_engine.connect() as conn:
        for role in _PROBE_ROLES:
            exists = conn.execute(
                text("SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = :role)"),
                {"role": role},
            ).scalar_one()
            assert exists, f"probe role {role} is missing; the fixture did not run"
            for schema, table in (
                ("public", "workspace_login_states"),
                ("mod_appdir", "application_bindings"),
            ):
                held = effective_privileges(conn, role=role, schema=schema, table=table)
                assert not held, (
                    f"probe role {role} holds {sorted(held)} on "
                    f"{schema}.{table} — the sensitivity fixture has reached "
                    "an object this suite makes claims about"
                )
