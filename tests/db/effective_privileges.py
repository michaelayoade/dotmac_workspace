"""Privilege questions asked the way the executor answers them.

Governance **ADR 0022 § 3 property 9** (Accepted 2026-08-30) makes the METHOD
part of the property, and it is right to: the obvious method passes when the
system is broken.

`information_schema.table_privileges` and its relatives enumerate **DIRECT**
grants. A role that reaches a table through a role MEMBERSHIP appears in that
view as holding nothing, so an isolation assertion built on it returns "no
privilege found" and goes green over exactly the leak it exists to detect. This
repository shipped that bug — these helpers replace it — and the recovery lane's
first draft inherited it before catching it. Two independent implementations
reached for the listing first, which is why the correction is a shared helper
with the reasoning attached rather than an edit to one query.

`has_table_privilege` and `has_any_column_privilege` resolve membership,
inheritance and `PUBLIC` the way the executor does. Three properties follow, and
each of them is a narrowing ADR 0022 explicitly refuses:

- **All seven table privileges**, never `SELECT` alone. A role holding `INSERT`,
  `UPDATE`, `DELETE` or `TRUNCATE` on a table it must not reach has crossed the
  boundary without ever reading a row, and `REFERENCES` and `TRIGGER` are reach
  as well.
- **Column granularity, not just table granularity.** A column-level grant
  leaves `has_table_privilege` false while the column is readable, so a check
  stopping at the table reports isolation over a live path.
- **Both directions.** A required-access assertion is as load-bearing as a
  forbidden-access one: a plane revoked from ITSELF passes every "cannot reach"
  assertion and cannot serve a request.

`tests/db/test_effective_privilege_method.py` plants a reach that exists ONLY
through a role membership and observes both halves — the discredited listing
missing it, and these helpers refusing it. Without that pairing the replacement
would be an assertion about itself.

The shape is ported, not invented: `dotmac_kernel.migrations.catalog`'s
`ROLE_TABLE_PRIVILEGES_SQL` is the fleet's proven form of this query
(ADR-0006's product-first rule).

A role that does not exist makes `has_table_privilege` RAISE, and that is the
wanted behaviour: a missing role is a failed property, never a quiet empty set.
"""

from __future__ import annotations

from typing import Final

from sqlalchemy import Connection, text

#: Every table privilege PostgreSQL has. The seven-ness of the check lives HERE,
#: once — a caller cannot silently test a subset, and a future PostgreSQL
#: privilege is added in one place.
TABLE_PRIVILEGES: Final[tuple[str, ...]] = (
    "SELECT",
    "INSERT",
    "UPDATE",
    "DELETE",
    "TRUNCATE",
    "REFERENCES",
    "TRIGGER",
)

#: The four that can be granted on a COLUMN. `has_any_column_privilege` rejects
#: the other three outright, so the distinction is PostgreSQL's, not a taste.
COLUMN_GRANTABLE_PRIVILEGES: Final[frozenset[str]] = frozenset(
    {"SELECT", "INSERT", "UPDATE", "REFERENCES"}
)

# The relation is located by `pg_class.oid` rather than by a text name so the
# privilege functions bind to their oid overload unambiguously, and so a
# misspelled table yields no row — a loud failure — instead of a false answer.
#
# The role and privilege are CAST explicitly. Both functions are overloaded on
# their first argument (`name` and `oid` forms), and an unknown-typed parameter
# there is resolved by preference rather than by declaration — a cast makes the
# overload the one intended rather than the one chosen for us.
_EFFECTIVE_TABLE_SQL: Final[str] = (
    "SELECT has_table_privilege("
    "    CAST(:role AS name), c.oid, CAST(:privilege AS text)) "
    "FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace "
    "WHERE n.nspname = :schema AND c.relname = :table AND c.relkind = 'r'"
)

_EFFECTIVE_TABLE_OR_COLUMN_SQL: Final[str] = (
    "SELECT has_table_privilege("
    "        CAST(:role AS name), c.oid, CAST(:privilege AS text)) "
    "    OR has_any_column_privilege("
    "        CAST(:role AS name), c.oid, CAST(:privilege AS text)) "
    "FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace "
    "WHERE n.nspname = :schema AND c.relname = :table AND c.relkind = 'r'"
)

# The DISCREDITED method, kept for ONE purpose: to be observed missing a reach
# the effective check refuses. Nothing may assert isolation from it.
_DIRECT_GRANT_LISTING_SQL: Final[str] = (
    "SELECT privilege_type FROM information_schema.table_privileges "
    "WHERE table_schema = :schema AND table_name = :table AND grantee = :role"
)


def _ask(
    conn: Connection,
    *,
    include_columns: bool,
    role: str,
    schema: str,
    table: str,
) -> frozenset[str]:
    held: set[str] = set()
    for privilege in TABLE_PRIVILEGES:
        column_grantable = privilege in COLUMN_GRANTABLE_PRIVILEGES
        sql = (
            _EFFECTIVE_TABLE_OR_COLUMN_SQL
            if include_columns and column_grantable
            else _EFFECTIVE_TABLE_SQL
        )
        answer = conn.execute(
            text(sql),
            {
                "role": role,
                "schema": schema,
                "table": table,
                "privilege": privilege,
            },
        ).scalar_one()
        if answer:
            held.add(privilege)
    return frozenset(held)


def effective_privileges(
    conn: Connection, *, role: str, schema: str, table: str
) -> frozenset[str]:
    """Which of the seven table privileges `role` EFFECTIVELY holds.

    Table or column, resolving memberships, inheritance and `PUBLIC` — the
    question ADR 0022 § 3 property 9 requires, asked by the same machinery that
    will answer it at runtime.
    """
    return _ask(conn, include_columns=True, role=role, schema=schema, table=table)


def table_level_privileges_only(
    conn: Connection, *, role: str, schema: str, table: str
) -> frozenset[str]:
    """`has_table_privilege` ALONE — deliberately blind to a column grant.

    One of the two narrowings ADR 0022 refuses, present so the sensitivity proof
    can watch it miss a column-only reach. Never an isolation assertion.
    """
    return _ask(conn, include_columns=False, role=role, schema=schema, table=table)


def direct_grant_listing(
    conn: Connection, *, role: str, schema: str, table: str
) -> frozenset[str]:
    """The DISCREDITED method: `information_schema.table_privileges`.

    Direct grants to the named grantee only. It cannot see a privilege reaching
    the role through a membership, through `PUBLIC`, or through a column grant,
    so an empty result from it is not evidence of anything.

    It exists in this repository at exactly one call site — the sensitivity
    proof that observes it missing a planted membership-only reach. An isolation
    assertion built on it is the defect ADR 0022 § 3 property 9 forbids, and
    `tests/test_isolation_proof_method.py` fails the build if one reappears.
    """
    return frozenset(
        row[0]
        for row in conn.execute(
            text(_DIRECT_GRANT_LISTING_SQL),
            {"role": role, "schema": schema, "table": table},
        )
    )


__all__ = [
    "COLUMN_GRANTABLE_PRIVILEGES",
    "TABLE_PRIVILEGES",
    "direct_grant_listing",
    "effective_privileges",
    "table_level_privileges_only",
]
