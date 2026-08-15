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

from dotmac_workspace.identity.config import configuration_errors
from dotmac_workspace.identity.feature import feature as identity_feature
from dotmac_workspace.identity.secret_bootstrap import install_workspace_secrets
from dotmac_workspace.launcher.feature import feature as launcher_feature

ASSEMBLY_NAME = "dotmac_workspace"


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
            dotmac_application_directory.module,
        ),
        web_enabled=True,
        startup_checks=(configuration_errors,),
        startup_hooks=(install_workspace_secrets,),
    )


__all__ = ["ASSEMBLY_NAME", "build_spec"]
