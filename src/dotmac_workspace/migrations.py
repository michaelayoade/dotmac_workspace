"""Compose the Workspace's migration lineages.

Three separately-owned lineages, one revision graph:

1. the KERNEL base lineage (`dotmac_kernel.migrations.versions_dir()`),
2. the APPLICATION DIRECTORY module's lineage
   (`dotmac_application_directory.versions_dir()`),
3. this repository's own `alembic/versions`.

Composed programmatically rather than hard-coded in `alembic.ini` because both
dependencies are INSTALLED packages whose paths are environment-specific — a
virtualenv, a wheel, a container layer. Each is located through its owner's
public locator, never by reaching into `__file__`.

Locations are only half of the composition. The other half is LOGICAL ordering:
`dotmac-application-directory` declares the database effects its lineage needs
(`requires`) and never names a foreign revision, so this assembly binds each
effect to the revision that supplies it — `dotmac_workspace.migration_bindings`,
installed by `alembic/env.py` and pointed at by `DOTMAC_MIGRATION_BINDINGS` for
the graph commands that never run `env.py`.

The Workspace database is its own (ADR-0021 §1). Nothing here knows a product
DSN, and nothing in this repository connects to one.

Import-safe: builds an Alembic `Config` only. It constructs no engine.
"""

from __future__ import annotations

import os
from pathlib import Path

from alembic.config import Config
from dotmac_application_directory import versions_dir as directory_versions_dir
from dotmac_kernel.migrations import versions_dir as kernel_versions_dir
from dotmac_kernel.prerequisites import BINDINGS_ENV_VAR

from dotmac_workspace.migration_bindings import BINDINGS_REF

REPO_ROOT = Path(__file__).resolve().parents[2]
ALEMBIC_DIR = REPO_ROOT / "alembic"
WORKSPACE_VERSIONS = ALEMBIC_DIR / "versions"


def composed_version_locations() -> str:
    """`<kernel> <application directory> <workspace>` — the three lineages."""
    return " ".join(
        str(location)
        for location in (
            kernel_versions_dir(),
            directory_versions_dir(),
            WORKSPACE_VERSIONS,
        )
    )


def make_alembic_config(url: str) -> Config:
    """An Alembic `Config` wired to all three lineages and the given URL.

    Used by the deploy entrypoint and by the migration tests, so CLI-vs-test
    composition can never diverge — the failure mode where a migration passes
    in tests and is missing in production.
    """
    cfg = Config(str(REPO_ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(ALEMBIC_DIR))
    cfg.set_main_option("version_locations", composed_version_locations())
    # env.py reads the migration URL from the environment. DATABASE_URL is set
    # too because env.py imports kernel modules that construct the kernel engine
    # at import time (they never connect here).
    os.environ["MIGRATION_DATABASE_URL"] = url
    os.environ.setdefault("DATABASE_URL", url)
    # `env.py` installs the bindings directly for an `upgrade`, but Alembic's
    # graph commands (`heads`, `history`, `show`) build the revision map without
    # running `env.py` at all — so a composed module's `resolve_depends_on`
    # would see no bindings and the INSPECTED graph would omit the cross-lineage
    # edge that the applied graph has. Exporting the pointer keeps both faithful.
    # Assigned, not `setdefault`: this assembly's answer is the authoritative
    # one for a Config it built itself.
    os.environ[BINDINGS_ENV_VAR] = BINDINGS_REF
    return cfg


__all__ = [
    "ALEMBIC_DIR",
    "REPO_ROOT",
    "WORKSPACE_VERSIONS",
    "composed_version_locations",
    "make_alembic_config",
]
