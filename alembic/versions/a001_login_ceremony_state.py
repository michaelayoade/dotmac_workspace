"""The login ceremony's shared, atomic state — this assembly's own first table.

Lineage ROOT for the `assembly` owner: `down_revision = None`, one branch
label, tables in `public` (the host schema the kernel and the one host assembly
share — `dotmac_kernel.namespaces.HOST_SCHEMA`). Cross-lineage ordering is
`depends_on`, never `down_revision`: splicing two independently released
lineages into one chain makes either of them un-releasable.

## What the table is for

An OIDC login starts on one worker and finishes on another — the browser goes
to the identity provider and comes back to whichever process the load balancer
picks. Any per-process store makes completion a coin flip, and the symptom is
an intermittent "login sometimes fails" that reproduces nowhere.

So the ceremony lives in the one Workspace database, and `consume` is a single
`DELETE … RETURNING` (see `dotmac_workspace.identity.state_store`). That is
what makes a state single-use across every worker without a lock, a queue or a
retry: under READ COMMITTED a row another transaction has already deleted drops
out of the result, so exactly one caller receives it.

## Hard rule 11, in full

`tenant_id NOT NULL`, a composite unique that INCLUDES `tenant_id`, RLS
ENABLEd *and* FORCEd, a tenant-isolation policy, and the online role's grants.
FORCE matters and is easy to omit: without it the table owner — which is the
role migrations run as — bypasses its own policy, and every canary that
arranges rows as the owner would prove nothing.

`DELETE` is granted alongside `SELECT`/`INSERT` because consuming a ceremony IS
a delete. `UPDATE` is deliberately NOT granted: nothing in this flow amends a
ceremony, and a state store whose rows can be edited is one where a verifier
can be swapped for one the attacker knows.

`platform_api` gets nothing. A login ceremony is a tenant's, mid-flight, and
the vendor control plane has no business in one.

## What the table deliberately does not hold

No party, no email, no subject, no claim. A ceremony is anonymous until the
callback verifies an ID token — nothing here identifies who is signing in, and
a column that did would be a record of every attempted sign-in whether or not
it succeeded.

`state_hash`, not the state: the state is a bearer value for the life of one
ceremony, and a database dump, a replica or a logged query plan should not hand
anybody a usable one.

Revision ID: a001_login_ceremony_state
Revises: (lineage root)
Create Date: 2026-08-15
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from dotmac_kernel.migrations.verify import require_prerequisites
from dotmac_kernel.prerequisites import resolve_depends_on

revision = "a001_login_ceremony_state"
down_revision = None
branch_labels = ("assembly",)

# This lineage needs a tenant catalogue for its foreign key and the database
# roles to grant to. It names the EFFECTS, not the revision — and this assembly
# answers both in `src/dotmac_workspace/migration_bindings.py`, which
# `alembic/env.py` installs before the revision map is built. Literals, not
# imported constants, so the composed gate can read them without importing this
# file.
REQUIRES = ("tenant_scope_catalog.v1", "module_database_roles.v1")

depends_on = resolve_depends_on(REQUIRES)

_TABLE = "workspace_login_states"


def upgrade() -> None:
    # A binding is a claim about the database, so it is proven against the
    # database before any DDL runs rather than trusted from a Python file.
    require_prerequisites(op.get_bind(), REQUIRES)

    op.create_table(
        _TABLE,
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        # sha256 hex of the opaque state the provider echoes back.
        sa.Column("state_hash", sa.String(64), nullable=False),
        # PKCE. 43 to 128 characters by RFC 7636; this client generates 86.
        sa.Column("code_verifier", sa.String(128), nullable=False),
        sa.Column("nonce", sa.String(64), nullable=False),
        # Where the member was going. Stored here rather than carried through
        # the provider, so nothing echoed back can become an open redirect.
        sa.Column("return_path", sa.String(500), nullable=False),
        # WHICH configured provider registration this ceremony belongs to —
        # the trusted half of the kernel's resolution tuple. 80 characters
        # matches `external_identity_bindings.provider_binding`.
        sa.Column("provider_binding", sa.String(80), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["tenant_id"],
            ["public.tenants.id"],
            ondelete="CASCADE",
            name="fk_workspace_login_states_tenant",
        ),
        # The consume path's key. Composite with `tenant_id` (hard rule 11) —
        # and correct on its own terms too: a state is one tenant's ceremony,
        # so uniqueness that spanned tenants would be a cross-tenant namespace
        # nothing needs.
        sa.UniqueConstraint(
            "tenant_id",
            "state_hash",
            name="uq_workspace_login_states_tenant_state",
        ),
        schema="public",
    )
    # Serves the opportunistic sweep in `PostgresStateStore.start`, which is
    # what keeps this table small without a scheduled job this assembly has
    # nowhere to run.
    op.create_index(
        "ix_workspace_login_states_tenant_expiry",
        _TABLE,
        ["tenant_id", "expires_at"],
        schema="public",
    )

    # Literal SQL, never built from a loop variable: the composed migration
    # gate reads this file statically without importing it, so a computed
    # statement is uninspectable and fails closed — correctly.
    op.execute("ALTER TABLE public.workspace_login_states ENABLE ROW LEVEL SECURITY;")
    op.execute("ALTER TABLE public.workspace_login_states FORCE ROW LEVEL SECURITY;")
    op.execute(
        """
        CREATE POLICY workspace_login_states_tenant_isolation
            ON public.workspace_login_states
            USING (tenant_id = public.app_current_tenant_id())
            WITH CHECK (tenant_id = public.app_current_tenant_id());
        """
    )
    # No UPDATE: see the module docstring. Consuming a ceremony is a DELETE,
    # and nothing amends one.
    op.execute(
        "GRANT SELECT, INSERT, DELETE ON public.workspace_login_states TO app_user;"
    )


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS public.workspace_login_states CASCADE;")
