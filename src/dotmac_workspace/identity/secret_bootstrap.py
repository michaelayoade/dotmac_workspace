"""The client secret is HELD, never dereferenced on a request path (ADR-0009).

## The rule, and what it means here

`dotmac_kernel.secret_sources` states it as a property of the kernel: nothing
resolves a secret from a store while handling a request. This module is the
Workspace's half of that bargain — the PRODUCT reads the secret from wherever
this deployment keeps it, once, at startup, and installs it. Afterwards
`require_secret` is a dictionary lookup, which is why calling it inside the
token exchange is not a violation of anything: the value is already in memory
and no code path from an HTTP request reaches a store.

Why be absolute about it on a login path specifically:

* A store outage would take the front door down. A process that already holds
  what it needs is untouched by a store that becomes unreachable an hour later.
* A store that answers SLOWLY is worse than one that fails: the latency lands
  on the callback, and the symptom is "logging in is slow", which nobody traces
  to a secret store.
* Fetch-per-request is also fetch-per-attacker. A login endpoint is the most
  reachable surface a deployment has; it should not be a lever on the store.

## The source this product supplies

`EnvironmentSecretSource` reads `WORKSPACE_OIDC_CLIENT_SECRET`, or the contents
of the file named by `WORKSPACE_OIDC_CLIENT_SECRET_FILE` — the file form being
what a Kubernetes secret mount, a systemd credential or a Bao agent template
produces. It is deliberately the *only* source shipped: a deployment that keeps
the secret in OpenBao or a cloud manager writes its own `SecretSource` and
installs it instead, and that dependency stays out of this repository exactly
as the kernel keeps it out of itself.

It raises rather than returning an empty mapping when it cannot supply the
secret, because an empty mapping is indistinguishable from "nothing is
configured" — the kernel's contract says so and it is the difference between a
loud boot failure and a silent one.

## No degraded start, and no degraded absence either

A deployment that HAS configured a provider must have its secret: installing
the source is a statement that the secret is expected, and a failure raises at
install, inside the lifespan, before the process serves anything.

A deployment that has configured NO provider installs nothing. That is not a
degraded start — there is no login surface to degrade — and
`config.configuration_errors()` is what decides whether it is acceptable, under
the kernel's environment policy: a warning in development, fatal in production.
"""

from __future__ import annotations

import logging
import os
from collections.abc import Mapping
from pathlib import Path
from typing import Final

from dotmac_kernel.secret_sources import (
    SecretSourceError,
    install_secret_source,
    require_secret,
)

from dotmac_workspace.identity import config

logger = logging.getLogger(__name__)

#: The held name. Namespaced so a deployment holding several products' secrets
#: in one source cannot collide on `client_secret`.
CLIENT_SECRET_NAME: Final[str] = "workspace.oidc.client_secret"

CLIENT_SECRET_ENV: Final[str] = "WORKSPACE_OIDC_CLIENT_SECRET"
CLIENT_SECRET_FILE_ENV: Final[str] = "WORKSPACE_OIDC_CLIENT_SECRET_FILE"


class EnvironmentSecretSource:
    """The Workspace's default `SecretSource`: environment, or a mounted file.

    Read ONCE by `install_secret_source`, and again only on an explicit
    `refresh_secrets()`. It may therefore do I/O — reading a mounted file here
    is fine, and reading one per request would not be.
    """

    def load(self) -> Mapping[str, str]:
        """The client secret, by name. Raises if it cannot be supplied.

        Never logs, repr's or raises the VALUE — only the names involved. A
        message that quotes what it choked on is a message that leaks the
        secret into whatever collects logs.
        """
        path = os.getenv(CLIENT_SECRET_FILE_ENV, "").strip()
        if path:
            try:
                value = Path(path).read_text(encoding="utf-8").strip()
            except OSError as exc:
                raise SecretSourceError(
                    f"{CLIENT_SECRET_FILE_ENV} names {path!r}, which could not "
                    f"be read: {type(exc).__name__}"
                ) from exc
            if not value:
                raise SecretSourceError(
                    f"{CLIENT_SECRET_FILE_ENV} names {path!r}, which is empty"
                )
            return {CLIENT_SECRET_NAME: value}

        value = os.getenv(CLIENT_SECRET_ENV, "").strip()
        if not value:
            raise SecretSourceError(
                f"neither {CLIENT_SECRET_ENV} nor {CLIENT_SECRET_FILE_ENV} "
                "supplies the OIDC client secret. A configured provider "
                "without its secret cannot complete a single login, so this "
                "fails at startup rather than at the first callback."
            )
        return {CLIENT_SECRET_NAME: value}


def install_workspace_secrets() -> None:
    """Startup hook: hold the configuration and the secret, once, for good.

    Order matters and is deliberate. The provider configuration is read and
    held FIRST, so that `config.provider()` is answerable for the rest of the
    process; the secret source is installed only when a provider exists,
    because a deployment with no login surface has no secret to expect.

    An exception here fails startup, which is the kernel's contract for a
    startup hook and the correct outcome: a Workspace whose members cannot log
    in should not be serving.
    """
    installed = config.install(config.load())
    if installed is None:
        logger.warning(
            "No OIDC provider configured — %s is unavailable in this process. "
            "Set %s, %s and %s to enable it.",
            "federated login",
            config.ISSUER_ENV,
            config.CLIENT_ID_ENV,
            config.REDIRECT_URL_ENV,
        )
        return

    names = install_secret_source(EnvironmentSecretSource())
    # Names, never values. The kernel logs the same way and for the same
    # reason; this line is here so an operator can see at a glance that the
    # secret was loaded at BOOT and not later.
    logger.info(
        "Federated login configured for issuer %s (provider binding %r); "
        "holding %d secret(s): %s",
        installed.issuer,
        installed.provider_binding,
        len(names),
        ", ".join(names),
    )


def client_secret() -> str:
    """The held client secret. A dictionary lookup — safe on a request path.

    Deliberately a function rather than a module constant: a constant would be
    bound at IMPORT time, which happens before the lifespan has installed
    anything, and would freeze whatever was (not) there then.
    """
    return require_secret(CLIENT_SECRET_NAME)


__all__ = [
    "CLIENT_SECRET_ENV",
    "CLIENT_SECRET_FILE_ENV",
    "CLIENT_SECRET_NAME",
    "EnvironmentSecretSource",
    "client_secret",
    "install_workspace_secrets",
]
