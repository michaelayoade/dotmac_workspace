"""The one `OIDCClient` this process holds, built from this deployment's config.

This module is all that remains of what used to be `identity/oidc.py` — a
complete, local OIDC implementation: discovery, JWKS with `kid` rotation, the
algorithm allow-list, PKCE, the token exchange and ID-token verification. It was
deleted, not refactored. `dotmac-auth-oidc 0.1.0a1` owns that protocol for the
whole fleet, and a second implementation of it in an assembly is a second place
for a signature check to be wrong.

What is left here is composition: which config, which lifetime, and where the
store comes from. That is genuinely this assembly's decision and belongs here.

## Why the client is held and the store is not

The client is built ONCE per process because it owns the `ProviderCache`.
Rebuilding it per request would refetch the discovery document and the key set
on every sign-in and lose the rate-limited refetch that handles a provider
rotating its `kid`.

The STORE cannot be held for that long. `PostgresStateStore` carries one
request's `Session`, and `dotmac_kernel.db` decides when that transaction opens
and commits (AGENTS.md hard rule 8). A client holding a session would be a
second transaction authority — the ceremony would commit at a different moment
from everything else the request did.

So the client is constructed with `PER_REQUEST_STATE_STORE`, which is a positive
declaration that a store arrives with each call rather than an absence. Forget
to pass one and the package raises naming the argument, instead of quietly
losing the PKCE verifier.

## The client secret is HELD, never fetched here

`secret_bootstrap.client_secret()` is a dictionary lookup over material the
product installed at startup (ADR-0009). Nothing on this path reaches a secret
store, and the secret is read at CLIENT-BUILD time, not per request — one more
reason the client is a process-lifetime object.

## Cache invalidation is by identity, not by TTL

The client is rebuilt when the `ProviderConfig` it was built from is no longer
the same object. Config is resolved once and held for the process, so in
production this happens exactly never; in tests it is what lets one test's
provider not leak into the next. There is deliberately no timed refresh — the
thing that expires is inside the `ProviderCache`, where the package manages it.
"""

from __future__ import annotations

from dotmac_auth_oidc import (
    PER_REQUEST_STATE_STORE,
    OIDCClient,
    RelyingPartyConfig,
)

from dotmac_workspace.identity.config import ProviderConfig
from dotmac_workspace.identity.secret_bootstrap import client_secret

_HELD: tuple[ProviderConfig, OIDCClient] | None = None


def _build(config: ProviderConfig) -> OIDCClient:
    return OIDCClient(
        RelyingPartyConfig(
            issuer=config.issuer,
            client_id=config.client_id,
            client_secret=client_secret(),
            redirect_uri=config.redirect_url,
            provider_binding=config.provider_binding,
            scopes=tuple(config.scopes.split()),
            discovery_url=config.discovery_url,
        ),
        # The store arrives per ceremony operation — see the module docstring.
        state_store=PER_REQUEST_STATE_STORE,
        timeout=config.http_timeout_seconds,
        leeway=config.clock_skew_seconds,
    )


def client(config: ProviderConfig) -> OIDCClient:
    """The held client for `config`, building it on first use."""
    global _HELD
    if _HELD is None or _HELD[0] is not config:
        _HELD = (config, _build(config))
    return _HELD[1]


def reset() -> None:
    """Drop the held client. Tests only — a process has one provider."""
    global _HELD
    _HELD = None


__all__ = ["client", "reset"]
