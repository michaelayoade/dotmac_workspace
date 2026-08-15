"""The `launcher` feature manifest — the Workspace's UI facet.

ADR-0021 records that the tenant portal is the ASSEMBLY's UI facet, not a domain
module. So the launcher lives here, in the assembly, while
`dotmac-application-directory` stays a domain the assembly composes. That split
is why the module ships no routers.

`core=False`: the launcher is a deletable surface. A Workspace deployment that
exposes only an API keeps the directory and drops this.

## The one permission it declares

`workspace.applications.read` — may this member see this tenant's connected
application portfolio. The launcher OWNS that code: a permission has exactly one
declaring module, and `create_app` refuses a composition in which two modules
declare the same one.

Declaring it here and referencing it from `guard.py` is what makes the reference
checkable rather than decorative. `create_app` walks every mounted route, reads
the permission code stamped on each guard, and validates it against the
catalogue built from the installed manifests. Delete this declaration and the
application stops booting — it does not quietly start serving the launcher to
every member of the tenant.

It is also not dead vocabulary (ADR-0008): the code has a real consumer, on the
one route that exists, in the same commit that declares it.
"""

from __future__ import annotations

from dotmac_kernel.features import FeatureManifest, NavItem

from dotmac_workspace.launcher.guard import APPLICATIONS_READ_PERMISSION
from dotmac_workspace.launcher.web import router

feature = FeatureManifest(
    name="launcher",
    web_routers=[router],
    nav=(NavItem(label="Applications", path="/applications"),),
    permissions=(APPLICATIONS_READ_PERMISSION,),
    core=False,
    enabled_by_default=True,
)

__all__ = ["feature"]
