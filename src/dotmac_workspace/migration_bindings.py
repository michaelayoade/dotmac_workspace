"""This assembly's answers to "which revision supplies that effect?".

A module lineage declares the database EFFECTS it needs
(`ModuleManifest.requires`, `dotmac_kernel.prerequisites`). It never names a
foreign revision, because the answer differs per assembly:
`dotmac-application-directory 0.1.0a3` requires `tenant_scope_catalog.v1` and
`module_database_roles.v1`, and says nothing about who provides them. This file
is where the **Workspace** answers.

It is the same class of decision as `version_locations` — which lineages are
composed, and which of their revisions supply the shared effects. The Workspace
composes the kernel's own base lineage, so both answers are kernel
`0001_initial_tenant_schema`. That is the easy case, and it is not the point:
the point is that the module says what it needs and this repository says who
supplies it, so the module stays installable into an assembly (ERP) that hosts
`public.tenants` in a lineage of its own and structurally cannot run kernel 0001.

**A binding is a claim, not a fact.** Nothing here is trusted:

- `dotmac_kernel.migrations.verify.require_prerequisites` re-proves each effect
  against the live catalog before `ad_0001` runs any DDL, so a stamped or
  aliased provider fails against the database rather than against this file;
- the order canary requires the named revision to already be recorded in
  `alembic_version`.

A wrong entry here therefore fails at `alembic upgrade`, before any DDL — which
is why `.github/workflows/ci.yml` runs the composed migration against a real
PostgreSQL rather than asserting this tuple's shape in a unit test.
"""

from __future__ import annotations

from typing import Final

from dotmac_kernel.prerequisites import (
    MODULE_DATABASE_ROLES_V1,
    TENANT_SCOPE_CATALOG_V1,
    PrerequisiteBinding,
)

#: Kernel `0001` creates `public.tenants`/`tenant_domains` and
#: `public.app_current_tenant_id()`, and ensures the three database roles
#: (`app_admin`, `app_user`, `platform_api`). It supplies far more than that —
#: people, credentials, sessions, RBAC, audit — which is exactly why a module
#: needing a foreign-key target declares the EFFECT rather than the revision.
KERNEL_TENANT_LINEAGE_REVISION: Final[str] = "0001_initial_tenant_schema"

ASSEMBLY_PREREQUISITE_BINDINGS: Final[tuple[PrerequisiteBinding, ...]] = (
    PrerequisiteBinding(
        prerequisite=TENANT_SCOPE_CATALOG_V1.name,
        provider_revision=KERNEL_TENANT_LINEAGE_REVISION,
        provider_owner="kernel",
    ),
    PrerequisiteBinding(
        prerequisite=MODULE_DATABASE_ROLES_V1.name,
        provider_revision=KERNEL_TENANT_LINEAGE_REVISION,
        provider_owner="kernel",
    ),
)

#: `module.path:ATTRIBUTE`, for `DOTMAC_MIGRATION_BINDINGS`. Alembic's graph
#: commands (`heads`, `history`, `show`) build the revision map WITHOUT running
#: `env.py`, so they never see what `env.py` installs; the environment variable
#: is the one channel both entry points share. Kept beside the bindings so the
#: pointer and the thing it points at cannot drift.
BINDINGS_REF: Final[str] = (
    "dotmac_workspace.migration_bindings:ASSEMBLY_PREREQUISITE_BINDINGS"
)

__all__ = [
    "ASSEMBLY_PREREQUISITE_BINDINGS",
    "BINDINGS_REF",
    "KERNEL_TENANT_LINEAGE_REVISION",
]
