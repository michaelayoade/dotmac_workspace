"""The `operator` feature manifest — the Workspace's administration facet.

Like the launcher, this lives in the ASSEMBLY rather than in a domain module:
ADR-0021 records that the tenant portal is the assembly's UI facet. It composes
`dotmac-application-directory` and the kernel's identity primitives; it defines
no tables of its own and ships no migration lineage.

`core=False`: an API-only Workspace deployment drops this surface and keeps the
CLI. That is a real deployment shape, not a hypothetical one — which is exactly
why the CLI is retained rather than deleted once the UI exists.

## The four codes it declares

Two read/manage pairs, over two different authorities — see `guard.py` for why
seeing a binding and creating one are deliberately not the same permission.
Each is declared here and referenced by exactly one guard; `create_app`
validates every mounted route's stamp against this catalogue, so a code that
loses its declaration stops the boot instead of silently opening a screen.

None of the four is dead vocabulary (ADR-0008): every code has a real consumer
on a real route in the same commit that declares it.
"""

from __future__ import annotations

from dotmac_kernel.features import FeatureManifest, NavItem

from dotmac_workspace.operator.guard import PERMISSIONS
from dotmac_workspace.operator.web import IDENTITY_PATH, MEMBERS_PATH, router

feature = FeatureManifest(
    name="operator",
    web_routers=[router],
    nav=(
        NavItem(label="Members", path=MEMBERS_PATH),
        NavItem(label="Identity", path=IDENTITY_PATH),
    ),
    permissions=PERMISSIONS,
    core=False,
    enabled_by_default=True,
)

__all__ = ["feature"]
