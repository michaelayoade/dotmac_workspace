"""The Workspace is an assembly, and it is its own plane (ADR-0021 §1).

ADR-0015's fleet-wide rule: an assembly that hand-builds its application does
not receive any control the kernel performs in `create_app`. This is the worst
application in the fleet to break that in, because its whole job is a security
boundary — and academy proved the failure is silent: a tenant lockdown that was
configured, asserted in config validation, and never armed.
"""

from __future__ import annotations

import ast
import inspect
from pathlib import Path

import dotmac_application_directory
from dotmac_kernel.assembly import ProductAssemblySpec

from dotmac_workspace import assembly, main

MAIN_SOURCE = Path(inspect.getfile(main)).read_text(encoding="utf-8")
ASSEMBLY_SOURCE = Path(inspect.getfile(assembly)).read_text(encoding="utf-8")


def test_the_app_is_built_by_create_app() -> None:
    """Not `FastAPI(...)`, and not its own lifespan."""
    assert "create_app" in MAIN_SOURCE
    assert "FastAPI(" not in MAIN_SOURCE
    assert "lifespan" not in MAIN_SOURCE


def test_the_spec_composes_the_directory_module() -> None:
    spec = assembly.build_spec()
    assert isinstance(spec, ProductAssemblySpec)
    assert dotmac_application_directory.module in spec.modules


def test_the_spec_does_not_compose_an_access_module() -> None:
    """Deferred by ADR-0021 §5 until the kernel has a generic signed-document
    mechanism. Asserting the ABSENCE so that adding it is a deliberate act that
    has to come back through this test — and through the ADR."""
    codes = {
        getattr(module, "code", getattr(module, "name", None))
        for module in assembly.build_spec().modules
    }
    assert "application_access" not in codes


def test_the_workspace_names_itself() -> None:
    """The assembly name reaches logs, metrics and the deployment profile. A
    Workspace that called itself anything else would be indistinguishable from
    a product data plane in an incident."""
    assert assembly.ASSEMBLY_NAME == "dotmac_workspace"
    assert assembly.build_spec().name == "dotmac_workspace"


def test_the_assembly_imports_no_product_data_plane() -> None:
    """No Sub, no ERP, no vendor control plane, no starter assembly.

    Cross-application integration is API/webhook only. An import would make the
    Workspace un-deployable without its siblings and would give it a route into
    another plane's tables — the shared-database failure ADR-0021 §1 forbids.
    """
    forbidden_roots = {"app", "vendor_cp", "dotmac_sub", "dotmac_erp"}
    package_root = Path(inspect.getfile(assembly)).parent
    for path in sorted(package_root.rglob("*.py")):
        if "__pycache__" in path.parts:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module:
                root = node.module.split(".")[0]
                assert root not in forbidden_roots, f"{path.name}: {node.module}"
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    root = alias.name.split(".")[0]
                    assert root not in forbidden_roots, f"{path.name}: {alias.name}"


def test_the_migration_composition_names_three_lineages() -> None:
    """Kernel, application directory, workspace — each located through its
    owner's public locator rather than by guessing at an installed path."""
    from dotmac_workspace.migrations import composed_version_locations

    locations = composed_version_locations().split()
    assert len(locations) == 3
    assert any("dotmac_kernel" in location for location in locations)
    assert any("dotmac_application_directory" in location for location in locations)
    assert locations[-1].endswith("alembic/versions")
