"""The OIDC authorization-code flow, with PKCE — the protocol half, alone.

`dotmac_kernel.external_identity` is explicit that it does no protocol: it
takes strings a caller has ALREADY verified and answers which local party they
name. This module is that caller's verification, and the division is worth
stating because getting it wrong is an authentication bypass rather than a bug:
**everything below runs before the kernel is asked anything, and the kernel
trusts what this module returns.**

## What is verified, in order

1. **Discovery metadata** is fetched from the configured URL and its `issuer`
   must equal the configured issuer (OpenID Connect Discovery §4.3). A document
   that names a different issuer is a document for a different provider.
2. **The code is redeemed** at the token endpoint over TLS, authenticated with
   `client_secret_basic`, carrying the PKCE `code_verifier` this browser's
   ceremony stored. An authorization code intercepted without the verifier is
   not redeemable.
3. **The ID token's signature** is checked against the provider's JWKS, with an
   explicit algorithm allow-list.
4. **The claims** are checked: `iss` against the metadata issuer, `aud` against
   this client id (plus `azp` when the audience is multi-valued), `exp`/`iat`
   with a configured leeway, and `nonce` against the value the ceremony stored.

Only then are `iss` and `sub` handed to the kernel.

## The algorithm allow-list is the whole defence against alg confusion

`ALLOWED_ALGORITHMS` contains asymmetric algorithms only. `none` is absent for
the obvious reason; every `HS*` is absent for the subtle one. A verifier that
accepts HMAC will happily validate a token an attacker signed with a value the
attacker knows — historically the provider's own public key, and in a
confidential client like this one, potentially the client secret itself. The
list is passed to `jwt.decode` explicitly, so the token's own header cannot
select the algorithm used to verify it.

## JWKS is a PUBLIC key document, and fetching it is not a secret lookup

ADR-0009 forbids dereferencing a SECRET on a request path. A JWKS is the
opposite of a secret — it is published, and it must be re-fetchable because
providers rotate signing keys without warning. It is cached for
`metadata_ttl_seconds` and re-fetched once when a token arrives with a `kid`
the cache does not hold, which is exactly the rotation case. The client secret,
which IS secret, is never fetched here: it is held from startup and read as a
dictionary lookup (`secret_bootstrap.client_secret`).

## What this module never does

No provider vocabulary leaks out of it: nothing downstream learns whether the
provider is Keycloak, Entra or anything else. No `roles`, `groups`, `scope` or
organization claim is read, stored or mapped — authorization is local, decided
by the kernel over local grants, and reading a provider's role claim is how an
identity provider quietly becomes an authorization authority.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import logging
import secrets
import threading
import time
from dataclasses import dataclass
from typing import Any, Final
from urllib.parse import urlencode

import httpx
import jwt

from dotmac_workspace.identity.config import ProviderConfig
from dotmac_workspace.identity.secret_bootstrap import client_secret

logger = logging.getLogger(__name__)

#: Asymmetric only. See the module docstring — this list, not the token's
#: header, decides how a signature is checked.
ALLOWED_ALGORITHMS: Final[tuple[str, ...]] = (
    "RS256",
    "RS384",
    "RS512",
    "PS256",
    "PS384",
    "PS512",
    "ES256",
    "ES384",
    "ES512",
)

#: Claims a usable ID token must carry. `nonce` is required separately below,
#: because PyJWT has no notion of it and its absence must be a refusal rather
#: than a comparison against `None`.
REQUIRED_CLAIMS: Final[tuple[str, ...]] = ("iss", "sub", "aud", "exp", "iat")

#: 64 URL-safe bytes → 86 characters, inside RFC 7636's 43-to-128 range.
_VERIFIER_BYTES: Final[int] = 64
_STATE_BYTES: Final[int] = 32
_NONCE_BYTES: Final[int] = 32


class OidcError(RuntimeError):
    """The ceremony cannot be completed.

    One exception type for every protocol failure, deliberately. A caller that
    could distinguish "unknown code" from "bad signature" from "wrong nonce"
    would be an oracle for whoever can drive a login, and the surface turns all
    of them into the same refusal anyway.
    """


@dataclass(frozen=True, slots=True)
class ProviderMetadata:
    """The three endpoints this flow needs, and the issuer that vouched."""

    issuer: str
    authorization_endpoint: str
    token_endpoint: str
    jwks_uri: str


@dataclass(frozen=True, slots=True)
class VerifiedSubject:
    """What the kernel is told: an issuer and a subject, both verified.

    Nothing else crosses this boundary. No email, no name, no claim bag — the
    kernel's binding table holds no such column, and a resolver that could see
    an email would eventually be asked to match on one.
    """

    issuer: str
    subject: str


def new_state() -> str:
    """The opaque ceremony id the provider echoes back. 256 bits."""
    return secrets.token_urlsafe(_STATE_BYTES)


def new_nonce() -> str:
    """Binds the ID token to this ceremony. 256 bits."""
    return secrets.token_urlsafe(_NONCE_BYTES)


def new_code_verifier() -> str:
    """The PKCE verifier. Stays in the state store; never leaves the server."""
    return secrets.token_urlsafe(_VERIFIER_BYTES)


def code_challenge(verifier: str) -> str:
    """`S256` — base64url(sha256(verifier)), unpadded.

    `plain` is not implemented and must not be: it makes the challenge equal to
    the verifier, so anyone who can read the authorization request can complete
    the exchange, which is the entire attack PKCE exists to stop.
    """
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


# ── Metadata and keys ───────────────────────────────────────────────────────

# Held per process, guarded by a lock so two concurrent callbacks cannot both
# fetch. Not shared between workers on purpose: a public document with a TTL is
# the one thing in this flow that costs nothing to duplicate, and putting it in
# the database would add a writer to the request path for no gain.
_lock = threading.Lock()
_metadata: tuple[ProviderMetadata, float] | None = None
_jwks: tuple[dict[str, Any], float] | None = None


def reset_cache() -> None:
    """Drop the cached metadata and keys. For tests and for an explicit reload."""
    global _metadata, _jwks
    with _lock:
        _metadata = None
        _jwks = None


def _get_json(url: str, *, timeout: float) -> dict[str, Any]:
    """One bounded GET returning a JSON object, or `OidcError`.

    Every outbound call in this module carries the configured timeout. An
    unbounded call to an identity provider is an unbounded login request, and a
    provider that hangs would hold a worker per attempt.
    """
    try:
        response = httpx.get(url, timeout=timeout, follow_redirects=False)
        response.raise_for_status()
        document = response.json()
    except (httpx.HTTPError, ValueError) as exc:
        raise OidcError(f"could not read {url}: {type(exc).__name__}") from exc
    if not isinstance(document, dict):
        raise OidcError(f"{url} did not return a JSON object")
    return document


def metadata(config: ProviderConfig) -> ProviderMetadata:
    """The provider's discovery document, cached for its configured TTL."""
    global _metadata
    with _lock:
        cached = _metadata
    if cached is not None and cached[1] > time.monotonic():
        return cached[0]

    document = _get_json(config.discovery_url, timeout=config.http_timeout_seconds)

    # OpenID Connect Discovery §4.3: the document's issuer MUST match the one
    # used to build the request. Skipping this turns discovery into "whatever
    # that URL says", and the URL is configuration an operator may have typed.
    declared = str(document.get("issuer", "")).rstrip("/")
    if declared != config.issuer:
        raise OidcError(
            "the discovery document declares a different issuer than the one "
            "configured — refusing to federate to it"
        )

    resolved = ProviderMetadata(
        issuer=declared,
        authorization_endpoint=str(document.get("authorization_endpoint", "")),
        token_endpoint=str(document.get("token_endpoint", "")),
        jwks_uri=str(document.get("jwks_uri", "")),
    )
    for name, value in (
        ("authorization_endpoint", resolved.authorization_endpoint),
        ("token_endpoint", resolved.token_endpoint),
        ("jwks_uri", resolved.jwks_uri),
    ):
        if not value.startswith("https://"):
            raise OidcError(
                f"the discovery document's {name} is not an https URL — every "
                "endpoint in this flow carries either a secret or a signature"
            )

    with _lock:
        _metadata = (resolved, time.monotonic() + config.metadata_ttl_seconds)
    return resolved


def _key_document(
    config: ProviderConfig, provider: ProviderMetadata, *, force: bool
) -> dict[str, Any]:
    global _jwks
    if not force:
        with _lock:
            cached = _jwks
        if cached is not None and cached[1] > time.monotonic():
            return cached[0]
    document = _get_json(provider.jwks_uri, timeout=config.http_timeout_seconds)
    with _lock:
        _jwks = (document, time.monotonic() + config.metadata_ttl_seconds)
    return document


def _signing_key(
    config: ProviderConfig, provider: ProviderMetadata, *, kid: str | None
) -> Any:
    """The public key for `kid`, re-fetching ONCE if the cache does not hold it.

    The re-fetch is the rotation path and nothing more: it happens at most once
    per verification, so a stream of tokens carrying invented key ids cannot
    turn this into a request amplifier pointed at the provider.
    """
    for force in (False, True):
        document = _key_document(config, provider, force=force)
        try:
            key_set = jwt.PyJWKSet.from_dict(document)
        except Exception as exc:
            raise OidcError(
                f"the provider's JWKS could not be parsed: {type(exc).__name__}"
            ) from exc
        for candidate in key_set.keys:
            if kid is None or candidate.key_id == kid:
                return candidate.key
        if force:
            break
    raise OidcError("the ID token was signed with a key the provider does not publish")


# ── The two round trips ─────────────────────────────────────────────────────


def authorization_url(
    config: ProviderConfig,
    provider: ProviderMetadata,
    *,
    state: str,
    nonce: str,
    verifier: str,
) -> str:
    """Where the browser is sent to authenticate.

    Only three values travel: the opaque `state`, the `nonce`, and the S256
    `code_challenge`. The verifier, the return path and everything else the
    ceremony knows stay in the state store — which is what makes `state` safe
    to hand to a browser at all.
    """
    query = urlencode(
        {
            "response_type": "code",
            "client_id": config.client_id,
            "redirect_uri": config.redirect_url,
            "scope": config.scopes,
            "state": state,
            "nonce": nonce,
            "code_challenge": code_challenge(verifier),
            "code_challenge_method": "S256",
        }
    )
    separator = "&" if "?" in provider.authorization_endpoint else "?"
    return f"{provider.authorization_endpoint}{separator}{query}"


def _exchange(
    config: ProviderConfig,
    provider: ProviderMetadata,
    *,
    code: str,
    verifier: str,
) -> str:
    """Redeem the code; return the raw ID token.

    `client_secret_basic` rather than a form field: it is the OpenID Connect
    default, the most widely supported, and it keeps the secret out of the
    request body that error handlers and proxies most like to log.

    The secret itself is a dictionary lookup of material held since startup —
    no store is contacted here (ADR-0009, `secret_bootstrap`).
    """
    try:
        response = httpx.post(
            provider.token_endpoint,
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": config.redirect_url,
                "code_verifier": verifier,
            },
            auth=(config.client_id, client_secret()),
            timeout=config.http_timeout_seconds,
            follow_redirects=False,
            headers={"Accept": "application/json"},
        )
    except httpx.HTTPError as exc:
        raise OidcError(
            f"the token endpoint could not be reached: {type(exc).__name__}"
        ) from exc

    if response.status_code != httpx.codes.OK:
        # The status, never the body: a token-endpoint error body can echo the
        # request, and the request carried the code and the verifier.
        raise OidcError(
            f"the token endpoint refused the exchange (HTTP {response.status_code})"
        )
    try:
        payload = response.json()
    except ValueError as exc:
        raise OidcError("the token endpoint did not return JSON") from exc
    if not isinstance(payload, dict):
        raise OidcError("the token endpoint did not return a JSON object")

    id_token = payload.get("id_token")
    if not isinstance(id_token, str) or not id_token:
        raise OidcError("the token response carried no id_token")
    return id_token


def _verify(
    config: ProviderConfig,
    provider: ProviderMetadata,
    *,
    id_token: str,
    nonce: str,
) -> VerifiedSubject:
    """Check the signature and every claim this flow depends on."""
    try:
        header = jwt.get_unverified_header(id_token)
    except jwt.PyJWTError as exc:
        raise OidcError(f"malformed ID token: {type(exc).__name__}") from exc

    algorithm = header.get("alg")
    if algorithm not in ALLOWED_ALGORITHMS:
        raise OidcError(
            f"ID token algorithm {algorithm!r} is not accepted — this client "
            "verifies asymmetric signatures only"
        )

    key = _signing_key(config, provider, kid=header.get("kid"))
    try:
        claims = jwt.decode(
            id_token,
            key=key,
            algorithms=list(ALLOWED_ALGORITHMS),
            audience=config.client_id,
            issuer=provider.issuer,
            leeway=config.clock_skew_seconds,
            options={"require": list(REQUIRED_CLAIMS)},
        )
    except jwt.PyJWTError as exc:
        raise OidcError(f"the ID token did not verify: {type(exc).__name__}") from exc

    # A multi-valued audience means the token was minted for more than one
    # party, and OpenID Connect Core §3.1.3.7 then requires `azp` to name the
    # one it was issued FOR. Without this check a token legitimately issued to
    # another client that happens to list us would be accepted.
    audience = claims.get("aud")
    if isinstance(audience, list) and len(audience) > 1:
        if claims.get("azp") != config.client_id:
            raise OidcError(
                "the ID token has multiple audiences and its authorized party "
                "is not this client"
            )

    presented = claims.get("nonce")
    if not isinstance(presented, str) or not hmac.compare_digest(presented, nonce):
        raise OidcError("the ID token's nonce does not match this ceremony")

    subject = claims.get("sub")
    if not isinstance(subject, str) or not subject.strip():
        raise OidcError("the ID token carries no usable subject")

    return VerifiedSubject(issuer=provider.issuer, subject=subject.strip())


def complete_ceremony(
    config: ProviderConfig, *, code: str, verifier: str, nonce: str
) -> VerifiedSubject:
    """Redeem the code and verify the ID token. The whole protocol half.

    Returns the two strings the kernel resolves on, and raises `OidcError` for
    every failure — one type, because the surface turns them all into the same
    refusal and a caller able to tell them apart would be an oracle.
    """
    provider = metadata(config)
    id_token = _exchange(config, provider, code=code, verifier=verifier)
    return _verify(config, provider, id_token=id_token, nonce=nonce)


__all__ = [
    "ALLOWED_ALGORITHMS",
    "REQUIRED_CLAIMS",
    "OidcError",
    "ProviderMetadata",
    "VerifiedSubject",
    "authorization_url",
    "code_challenge",
    "complete_ceremony",
    "metadata",
    "new_code_verifier",
    "new_nonce",
    "new_state",
    "reset_cache",
]
