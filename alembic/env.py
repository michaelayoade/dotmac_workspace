"""Alembic environment — the Tenant Workspace's migration environment.

Connects as `app_admin` (the RLS-bypass migration role) — set
`MIGRATION_DATABASE_URL` or `DATABASE_URL`. `target_metadata` is the kernel
`Base` (all kernel models) PLUS the application-directory module's models, so
autogenerate sees the whole composed schema.

The three lineages' directories are composed programmatically
(`dotmac_workspace.migrations`), not in `alembic.ini`, because two of the three
are installed packages with environment-specific paths.

Their ORDERING is composed here too, and logically. A module lineage declares
the database effects it needs (`ModuleManifest.requires`) and never names a
foreign revision; the ASSEMBLY binds each effect to the revision that supplies
it. This file installs that binding set — see
`dotmac_workspace.migration_bindings`.
"""

from __future__ import annotations

import os
from logging.config import fileConfig

from alembic import context

# Register the module's models so `mod_appdir` is in the shared metadata.
from dotmac_application_directory import models as directory_models  # noqa: F401

# Register the kernel models so the shared Base.metadata is fully populated.
from dotmac_kernel import (  # noqa: F401
    audit,
    models_platform,
    settings_models,
)
from dotmac_kernel.messaging import models as messaging_models  # noqa: F401
from dotmac_kernel.models import Base
from dotmac_kernel.planes import install_module_plane_selections
from dotmac_kernel.prerequisites import install_prerequisite_bindings
from sqlalchemy import engine_from_config, pool

from dotmac_workspace.assembly import build_spec
from dotmac_workspace.migration_bindings import ASSEMBLY_PREREQUISITE_BINDINGS
from dotmac_workspace.migrations import composed_version_locations

config = context.config

# Ensure all three lineages are composed even if alembic is invoked without the
# programmatic Config (belt-and-braces for the online run).
if not config.get_main_option("version_locations"):
    config.set_main_option("version_locations", composed_version_locations())

# Installed BEFORE the revision map is built. A composed module lineage resolves
# its `depends_on` from these bindings at script-load time, so an assembly that
# composes a module without answering what that module requires fails loudly
# here rather than ordering wrongly and discovering it against a database.
#
# `install_` (not `setdefault`) on purpose: this is the assembly's answer, and
# there is exactly one per assembly.
install_prerequisite_bindings(ASSEMBLY_PREREQUISITE_BINDINGS)

# A SEPARATE declaration from the bindings above, and deliberately so (ADR-0028).
# A binding answers where a database effect comes from; it cannot also answer
# which part of a selectable module this product intends to install, because
# nothing is missing in that case and so nothing can be inferred. The Workspace's
# selection is empty today — `application_directory` has an atomic tenant plane —
# and it is read off the assembly spec rather than restated here, so the
# migration environment and the running application can never disagree.
install_module_plane_selections(
    config.attributes.get("module_plane_selections", build_spec().module_planes)
)

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


def get_url() -> str:
    return os.getenv("MIGRATION_DATABASE_URL") or os.getenv("DATABASE_URL") or ""


def run_migrations_offline() -> None:
    context.configure(
        url=get_url(),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    configuration = config.get_section(config.config_ini_section) or {}
    configuration["sqlalchemy.url"] = get_url()
    connectable = engine_from_config(
        configuration,
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    with connectable.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata)
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
