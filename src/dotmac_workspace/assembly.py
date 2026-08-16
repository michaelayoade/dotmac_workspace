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
- `operator.feature` — the administration facet: members, roles and identity
  bindings. Same reasoning as the launcher, and the reason the CLI is now a
  recovery path rather than the only way to administer a running deployment.

## What it deliberately does not compose

`dotmac-application-access` and signed grant sets. Deferred by ADR-0021 §5 until
the kernel has a generic signed-document mechanism — the licence envelope
verifier is private and hard-wired to its own schema, so the only three moves
available today (import the private verifier, disguise a grant as a licence,
copy the envelope) are all wrong. Until then this Workspace can show a portfolio
and cannot allocate access, and that gap is honest rather than papered over.
"""

from __future__ import annotations

from pathlib import Path

import dotmac_application_directory
import dotmac_ui
from dotmac_kernel.assembly import ProductAssemblySpec

from dotmac_workspace.identity.config import configuration_errors
from dotmac_workspace.identity.feature import feature as identity_feature
from dotmac_workspace.identity.secret_bootstrap import install_workspace_secrets
from dotmac_workspace.launcher.feature import feature as launcher_feature
from dotmac_workspace.operator.feature import feature as operator_feature

ASSEMBLY_NAME = "dotmac_workspace"

#: Where this assembly's own static assets live, resolved from the package
#: rather than the working directory — the app runs from `/app` in a container
#: and from a checkout in development, and a relative path would work in
#: exactly one of them.
_STATIC_DIR = Path(__file__).resolve().parent / "static"


def build_spec() -> ProductAssemblySpec:
    """Compose the Workspace assembly.

    `identity` is listed FIRST because it is the front door: a deployment that
    somehow mounted the launcher without it would serve an `/applications` that
    redirects to a `/login` that does not exist — which is exactly the state
    blocker B2 described, and the state this workstream closed.

    ## The two startup seams, and why the OIDC secret uses them

    `startup_checks` runs first and follows the kernel's environment policy: a
    warning in development, a fatal error in production. `configuration_errors`
    is therefore how a production Workspace whose members could not log in
    fails to start, rather than starting and looking healthy.

    `startup_hooks` then runs `install_workspace_secrets`, which reads the
    provider configuration and installs the `SecretSource` holding the OIDC
    client secret. Once, inside the lifespan, before a single request is
    served. ADR-0009: a secret is HELD, never dereferenced on a request path,
    so a secret store that becomes unreachable an hour after boot cannot touch
    the login path — and a store that is merely SLOW cannot put its latency on
    every callback.

    Both are kernel seams rather than module-level side effects. Reading a
    secret at import time would run it during `alembic`, during a CLI
    invocation and during collection of every test, none of which needs it.
    """
    return ProductAssemblySpec(
        name=ASSEMBLY_NAME,
        modules=(
            identity_feature,
            launcher_feature,
            operator_feature,
            dotmac_application_directory.module,
        ),
        web_enabled=True,
        # The design system's compiled assets, layered into the existing
        # `/static` mount. The kernel never imports `dotmac_ui` — the assembly
        # fills this slot, which is what keeps the dependency direction one-way.
        #
        # The spec's sibling `stylesheets` slot is deliberately NOT set here.
        # It installs a Jinja global, and this assembly renders no templates:
        # its one HTML shell is `page.py`, which emits the `<link>` itself from
        # the same `dotmac_ui.stylesheet_url()`. Declaring config that nothing
        # in this composition reads would be inert vocabulary — it would look
        # like the styling was wired when the actual wiring lived elsewhere,
        # which is the state a reader most needs not to be lied to about.
        packaged_static_dirs=(dotmac_ui.static_dir(),),
        # This assembly's own `.dmws-*` rules, written entirely against
        # `var(--dmui-*)` tokens. Separate from the package's assets because the
        # design system ships tokens and declared components; the markup that
        # consumes them is the product's.
        assembly_static_dir=_STATIC_DIR,
        startup_checks=(configuration_errors,),
        startup_hooks=(install_workspace_secrets,),
    )


__all__ = ["ASSEMBLY_NAME", "build_spec"]
