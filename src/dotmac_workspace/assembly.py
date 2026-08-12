"""The Tenant Workspace's `ProductAssemblySpec` — what this application IS.

ADR-0021 makes `dotmac_workspace` an independent ADR-0003 assembly: the
customer's plane, sitting between the vendor control plane (which issues what
the tenant commercially owns) and the target applications (which evaluate their
own roles).

## It composes `create_app`, it does not hand-build

ADR-0015's fleet-wide rule, and this is the worst possible application to break
it in: an assembly that builds its own FastAPI app silently declines every
control the kernel performs inside `create_app`, and this one's entire job is a
security boundary. Reading a kernel setting is not adopting the behaviour behind
it — academy proved that with a tenant lockdown that was configured, asserted in
config validation, and never armed.

## What it composes

- `dotmac_application_directory.module` — the domain: the tenant's
  connected-application portfolio, its lifecycle, and its reconciliation state.
- `launcher.feature` — the UI facet. Per ADR-0021 the portal is the assembly's
  facet rather than a domain module, which is why the directory ships no
  routers and this feature exists here.

## What it deliberately does not compose

`dotmac-application-access` and signed grant sets. Deferred by ADR-0021 §5 until
the kernel has a generic signed-document mechanism — the licence envelope
verifier is private and hard-wired to its own schema, so the only three moves
available today (import the private verifier, disguise a grant as a licence,
copy the envelope) are all wrong. Until then this Workspace can show a portfolio
and cannot allocate access, and that gap is honest rather than papered over.
"""

from __future__ import annotations

import dotmac_application_directory
from dotmac_kernel.assembly import ProductAssemblySpec

from dotmac_workspace.launcher.feature import feature as launcher_feature

ASSEMBLY_NAME = "dotmac_workspace"


def build_spec() -> ProductAssemblySpec:
    """Compose the Workspace assembly."""
    return ProductAssemblySpec(
        name=ASSEMBLY_NAME,
        modules=(
            launcher_feature,
            dotmac_application_directory.module,
        ),
        web_enabled=True,
    )


__all__ = ["ASSEMBLY_NAME", "build_spec"]
