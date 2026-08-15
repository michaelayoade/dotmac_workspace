"""The ONE deployment-configured OIDC provider, read once at startup.

## One provider, and why there is no registration table

This assembly federates to a single provider, named by environment
configuration. A multi-provider registration table — rows an administrator
creates, each with discovery URLs, a client id and its own secret half — is
deliberately **out of scope**, and not because it is hard.

It is a second contract with its own lifecycle: who may add a provider, how its
secret half is stored (ADR-0009 governs that, and a per-row secret is exactly
the shape the kernel refuses to dereference on a request path), what happens to
the bindings that name it when a row is deleted, and how a tenant-created
provider interacts with `provider_binding` being the trusted half of the
resolution tuple. Deciding that from imagination produces a wire format that has
to be unpicked in the field. It is decided from real demand or not at all.

What that costs today is stated plainly: a deployment federates to one issuer.
What it buys is that `provider_binding` stays a value an OPERATOR configured,
which is the whole basis on which `dotmac_kernel.external_identity` trusts it.

## Read once, held, never on a request path

`load()` reads the environment. It is called from the startup check and from
the startup hook, both inside the FastAPI lifespan, and its result is held by
`install()` for the rest of the process. Nothing on a request path reads the
environment — `tests/test_secret_is_held.py` proves it by AST over every module
this package's request handlers reach.

That is the same discipline `dotmac_kernel.secret_sources` applies to secret
material, applied to the non-secret half for the same reason: a value resolved
per request is a value whose provenance nobody can state, and a login path is
the worst place to discover that.

## Everything by config (AGENTS.md §7)

Every value below is an environment knob with a documented default. Nothing
hardcodes a host, a port, a path or a timeout.

| variable | default | meaning |
|---|---|---|
| `WORKSPACE_OIDC_ISSUER` | — | the provider's issuer URL; **enables** federated login |
| `WORKSPACE_OIDC_CLIENT_ID` | — | this relying party's client id |
| `WORKSPACE_OIDC_REDIRECT_URL` | — | the callback URL registered at the provider |
| `WORKSPACE_OIDC_PROVIDER_BINDING` | `primary` | the LOCAL name of this registration |
| `WORKSPACE_OIDC_SCOPES` | `openid` | space-separated scopes |
| `WORKSPACE_OIDC_DISCOVERY_URL` | `<issuer>` + well-known | the metadata document |
| `WORKSPACE_OIDC_HTTP_TIMEOUT_SECONDS` | `10` | every outbound call is bounded |
| `WORKSPACE_OIDC_METADATA_TTL_SECONDS` | `900` | discovery/JWKS cache lifetime |
| `WORKSPACE_OIDC_CEREMONY_TTL_SECONDS` | `600` | how long a started login may take |
| `WORKSPACE_OIDC_CLOCK_SKEW_SECONDS` | `60` | leeway on `exp`/`iat` |

`WORKSPACE_OIDC_SCOPES` deliberately defaults to `openid` alone. This assembly
reads exactly two claims — `iss` and `sub` — and asking a provider for profile
or email data it will never use is surface with no consumer. Provider roles,
groups and scopes are not read, not stored and not mapped: authorization is
local, decided by the kernel over local grants.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Final

#: Environment variable names, in one place so the docs table above and the
#: reader below cannot drift.
ISSUER_ENV: Final[str] = "WORKSPACE_OIDC_ISSUER"
CLIENT_ID_ENV: Final[str] = "WORKSPACE_OIDC_CLIENT_ID"
REDIRECT_URL_ENV: Final[str] = "WORKSPACE_OIDC_REDIRECT_URL"
PROVIDER_BINDING_ENV: Final[str] = "WORKSPACE_OIDC_PROVIDER_BINDING"
SCOPES_ENV: Final[str] = "WORKSPACE_OIDC_SCOPES"
DISCOVERY_URL_ENV: Final[str] = "WORKSPACE_OIDC_DISCOVERY_URL"
HTTP_TIMEOUT_ENV: Final[str] = "WORKSPACE_OIDC_HTTP_TIMEOUT_SECONDS"
METADATA_TTL_ENV: Final[str] = "WORKSPACE_OIDC_METADATA_TTL_SECONDS"
CEREMONY_TTL_ENV: Final[str] = "WORKSPACE_OIDC_CEREMONY_TTL_SECONDS"
CLOCK_SKEW_ENV: Final[str] = "WORKSPACE_OIDC_CLOCK_SKEW_SECONDS"

DEFAULT_PROVIDER_BINDING: Final[str] = "primary"
DEFAULT_SCOPES: Final[str] = "openid"
DEFAULT_HTTP_TIMEOUT_SECONDS: Final[float] = 10.0
DEFAULT_METADATA_TTL_SECONDS: Final[int] = 900
DEFAULT_CEREMONY_TTL_SECONDS: Final[int] = 600
DEFAULT_CLOCK_SKEW_SECONDS: Final[int] = 60

#: The discovery path every OpenID Provider serves, relative to its issuer.
WELL_KNOWN_SUFFIX: Final[str] = "/.well-known/openid-configuration"


class ProviderNotConfiguredError(RuntimeError):
    """No OIDC provider is configured in this deployment.

    Raised by `provider()` when the login surface is reached in a deployment
    that never configured one. `web.py` turns it into a 503 that says federated
    login is not configured — never a 500, and never a page that looks like a
    login form nobody can complete.
    """


@dataclass(frozen=True, slots=True)
class ProviderConfig:
    """One configured provider registration. Immutable, held for the process."""

    issuer: str
    client_id: str
    redirect_url: str
    provider_binding: str
    scopes: str
    discovery_url: str
    http_timeout_seconds: float
    metadata_ttl_seconds: int
    ceremony_ttl_seconds: int
    clock_skew_seconds: int


def _positive(name: str, raw: str, fallback: float) -> float:
    """A numeric knob, or its default. A non-positive value is a refusal.

    A timeout of zero is not "no timeout" — it is a call that can never
    succeed — and a TTL of zero would turn a cache into a fetch per request.
    Both are configuration mistakes worth failing on rather than absorbing.
    """
    if not raw.strip():
        return fallback
    try:
        value = float(raw)
    except ValueError as exc:
        raise ValueError(f"{name} must be a number, got {raw!r}") from exc
    if value <= 0:
        raise ValueError(f"{name} must be greater than zero, got {value}")
    return value


def load() -> ProviderConfig | None:
    """Read the environment. `None` when no provider is configured.

    `None` is a legitimate answer, not a failure: an API-only or
    not-yet-federated deployment has no login surface to serve. Whether that is
    ACCEPTABLE is a separate question, answered by `configuration_errors()`
    under the kernel's environment policy — a warning in development, fatal in
    production.

    Raises `ValueError` for a provider that is configured INCOMPLETELY, which
    is a different thing from one that is absent. A deployment that named an
    issuer and forgot the client id has made a mistake; one that named nothing
    has made a choice.
    """
    issuer = os.getenv(ISSUER_ENV, "").strip().rstrip("/")
    client_id = os.getenv(CLIENT_ID_ENV, "").strip()
    redirect_url = os.getenv(REDIRECT_URL_ENV, "").strip()

    if not issuer and not client_id and not redirect_url:
        return None

    missing = [
        name
        for name, value in (
            (ISSUER_ENV, issuer),
            (CLIENT_ID_ENV, client_id),
            (REDIRECT_URL_ENV, redirect_url),
        )
        if not value
    ]
    if missing:
        raise ValueError(
            "federated login is partially configured — "
            f"{', '.join(missing)} is unset. Configure the whole provider or "
            "none of it; a half-configured front door fails at the first login "
            "rather than at startup."
        )
    if not issuer.startswith("https://"):
        raise ValueError(
            f"{ISSUER_ENV} must be an https URL — an issuer reached over plain "
            "HTTP can be substituted by anything on the path"
        )

    return ProviderConfig(
        issuer=issuer,
        client_id=client_id,
        redirect_url=redirect_url,
        provider_binding=(
            os.getenv(PROVIDER_BINDING_ENV, "").strip() or DEFAULT_PROVIDER_BINDING
        ),
        scopes=os.getenv(SCOPES_ENV, "").strip() or DEFAULT_SCOPES,
        discovery_url=(
            os.getenv(DISCOVERY_URL_ENV, "").strip() or issuer + WELL_KNOWN_SUFFIX
        ),
        http_timeout_seconds=_positive(
            HTTP_TIMEOUT_ENV,
            os.getenv(HTTP_TIMEOUT_ENV, ""),
            DEFAULT_HTTP_TIMEOUT_SECONDS,
        ),
        metadata_ttl_seconds=int(
            _positive(
                METADATA_TTL_ENV,
                os.getenv(METADATA_TTL_ENV, ""),
                DEFAULT_METADATA_TTL_SECONDS,
            )
        ),
        ceremony_ttl_seconds=int(
            _positive(
                CEREMONY_TTL_ENV,
                os.getenv(CEREMONY_TTL_ENV, ""),
                DEFAULT_CEREMONY_TTL_SECONDS,
            )
        ),
        clock_skew_seconds=int(
            _positive(
                CLOCK_SKEW_ENV,
                os.getenv(CLOCK_SKEW_ENV, ""),
                DEFAULT_CLOCK_SKEW_SECONDS,
            )
        ),
    )


# The held configuration. One per process, installed at startup, read by the
# request path as a plain attribute lookup.
_held: ProviderConfig | None = None


def install(config: ProviderConfig | None) -> ProviderConfig | None:
    """Hold `config` for the process. Called once, from the startup hook."""
    global _held
    _held = config
    return _held


def provider() -> ProviderConfig:
    """The held configuration, or raise. A dict-free attribute read.

    No environment access, no I/O, no fallback: whatever startup installed is
    what every request sees, for the life of the process.
    """
    if _held is None:
        raise ProviderNotConfiguredError(
            "no OIDC provider is configured in this deployment — set "
            f"{ISSUER_ENV}, {CLIENT_ID_ENV} and {REDIRECT_URL_ENV}"
        )
    return _held


def provider_or_none() -> ProviderConfig | None:
    """The held configuration, without raising. For surfaces that degrade."""
    return _held


def configuration_errors() -> list[str]:
    """Product startup check — human-readable errors, per the kernel contract.

    `create_app` treats these as warnings in development and as fatal startup
    errors in production, which is the right asymmetry: a developer running the
    launcher without an identity provider should get a warning and a working
    process, and a production deployment whose members cannot log in should not
    start and pretend otherwise.
    """
    try:
        config = load()
    except ValueError as exc:
        return [str(exc)]
    if config is None:
        return [
            "federated login is not configured, so /login cannot complete — "
            f"set {ISSUER_ENV}, {CLIENT_ID_ENV} and {REDIRECT_URL_ENV}"
        ]
    return []


__all__ = [
    "CEREMONY_TTL_ENV",
    "CLIENT_ID_ENV",
    "CLOCK_SKEW_ENV",
    "DEFAULT_CEREMONY_TTL_SECONDS",
    "DEFAULT_PROVIDER_BINDING",
    "DISCOVERY_URL_ENV",
    "HTTP_TIMEOUT_ENV",
    "ISSUER_ENV",
    "METADATA_TTL_ENV",
    "PROVIDER_BINDING_ENV",
    "REDIRECT_URL_ENV",
    "SCOPES_ENV",
    "ProviderConfig",
    "ProviderNotConfiguredError",
    "configuration_errors",
    "install",
    "load",
    "provider",
    "provider_or_none",
]
