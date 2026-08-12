"""The `launcher` feature manifest — the Workspace's UI facet.

ADR-0021 records that the tenant portal is the ASSEMBLY's UI facet, not a domain
module. So the launcher lives here, in the assembly, while
`dotmac-application-directory` stays a domain the assembly composes. That split
is why the module ships no routers.

`core=False`: the launcher is a deletable surface. A Workspace deployment that
exposes only an API keeps the directory and drops this.

No `permissions` declaration yet. The one authorization decision this screen
makes — may this member see this tenant's portfolio — is `require_workspace_auth`,
which is authentication plus tenant scope rather than a permission code. A
finer-grained `workspace.applications.read` arrives with the screen that needs
it to differ from "is a member", and not before: a declared code with no
consumer is dead vocabulary that reads like a working gate (ADR-0008).
"""

from __future__ import annotations

from dotmac_kernel.features import FeatureManifest, NavItem

from dotmac_workspace.launcher.web import router

feature = FeatureManifest(
    name="launcher",
    web_routers=[router],
    nav=(NavItem(label="Applications", path="/applications"),),
    core=False,
    enabled_by_default=True,
)

__all__ = ["feature"]
